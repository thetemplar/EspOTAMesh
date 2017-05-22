/// Expose Espressif SDK functionality - wrapped in ifdef so that it still
// compiles on other platforms
#ifdef ESP8266
extern "C" {
#include "user_interface.h"
}
#endif

#define VERSION 0x02
//uint8_t VERSION;
#define START_TTL 0x05
#define MSG_TYPE 0x00
#define CHANNEL 1


#include "FS.h"
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <WiFiUdp.h>
#include <ArduinoOTA.h>
#include <WiFiClient.h>
#include <SimpleTimer.h>
#include <map>
#include "defines.h"
#include "ideOta.h"

WiFiClient client;
WiFiServer server(9900);



SimpleTimer timer;
bool requestedUpdate = false;

bool inProcess = false;
bool blinkOn = false;

struct sniffer_buf2 *sniffer;

uint16_t seqnum = 0x000;
std::map<uint32_t,uint16_t> lastSeqNum;

void createPacket(uint8_t* result, uint8_t *buf, uint16_t len, uint32_t dst, uint8_t type)
{
  memcpy(&result[0], &beacon_raw[0], sizeof(beacon_raw));
  memcpy(&result[sizeof(beacon_raw)], &buf[0], len);

  //dst
  result[4 + 2] = (dst >> 24) & 0xFF;
  result[4 + 3] = (dst >> 16) & 0xFF;
  result[4 + 4] = (dst >> 8) & 0xFF;
  result[4 + 5] = (dst) & 0xFF;

  //transmit
  result[10 + 2] = (ESP.getChipId() >> 24) & 0xFF;
  result[10 + 3] = (ESP.getChipId() >> 16) & 0xFF;
  result[10 + 4] = (ESP.getChipId() >> 8) & 0xFF;
  result[10 + 5] = (ESP.getChipId()) & 0xFF;

  //src
  result[16 + 2] = (ESP.getChipId() >> 24) & 0xFF;
  result[16 + 3] = (ESP.getChipId() >> 16) & 0xFF;
  result[16 + 4] = (ESP.getChipId() >> 8) & 0xFF;
  result[16 + 5] = (ESP.getChipId()) & 0xFF;

  result[22] = (seqnum & 0x0f) << 4;
  result[23] = (seqnum & 0xff0) >> 4;

  seqnum++;
  if (seqnum > 0xfff)
    seqnum = 0;

  result[39] += len;
  result[44] = type;
  result[42] = VERSION;
}

void forwardPacket(uint8_t* result)
{
  if(result[43] == 0) //double safty. if ttl is == 0, then make packet invalid
  {
    result[0] = 0;
    result[1] = 0;
  }

  //set transmitter
  result[16 + 2] = (ESP.getChipId() >> 24) & 0xFF;
  result[16 + 3] = (ESP.getChipId() >> 16) & 0xFF;
  result[16 + 4] = (ESP.getChipId() >> 8) & 0xFF;
  result[16 + 5] = (ESP.getChipId()) & 0xFF;

  //decrease ttl
  result[43]--;
}



void flashFirmware()
{
  File f = SPIFFS.open("/fw.bin", "r");
  if (!f) {
      Serial.println("file open failed");
  } 
  else
  {
    uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
    if (!Update.begin(maxSketchSpace)) { //start with max available size
      Update.printError(Serial);
      Serial.println("ERROR");
    }
    Serial.println("starting flash");
    while (f.available()) {
      uint8_t ibuffer[128];
      f.read((uint8_t *)ibuffer, 128);
      Update.write(ibuffer, sizeof(ibuffer));  
      Serial.print(".");      
    }        
    Serial.print(Update.end(true));
    Serial.println("done");
    Serial.println(Update.md5String());
    Serial.println(Update.hasError());
    Serial.println(Update.isFinished());
    delay(100);
    Serial.println("reboot");
    delay(100);
    ESP.restart();
  }
}

bool goToRequestMode(uint32_t otaHost)
{
  Serial.println("Trying to connect");
  wifi_promiscuous_enable(0);
  WiFi.mode(WIFI_STA); 
  const char* ap = (String("OTA_Update_") + String(otaHost)).c_str();
  const char* pw = (String("OTA_Update_") + String(ESP.getChipId())).c_str();
  Serial.printf ("Host AP: %s - Host PW: %s\n", ap, pw);
  WiFi.begin(ap, pw);

  int i = 0;
  while (WiFi.status() != WL_CONNECTED && i < 50) {
    delay(500);
    Serial.print(".");
    i++;
  }
  Serial.print("\n");
  if(i == 50)
  {
    Serial.println("failed (connection timed out)!");
    WiFi.disconnect();
    return false;
  }
  
  delay(100);
  IPAddress server(192,168,0,1);
  if ( !client.connect(server, 9900) ) {    
    Serial.println("failed (no connection to port 9900)!");
    WiFi.disconnect();
    return false;
  }


  uint8_t md5Inc[16];
  File f2 = SPIFFS.open("/fw.bin", "w");
  uint8_t buf[1024];
  int timeout = 100;
  while(!client.available()) { delay(100); timeout--; if (timeout <= 0) {stopHostMode(); return false; } }
  while(client.available()) {
    size_t len = client.readBytes(buf, 1024);
    f2.write(buf, len);
    yield();    
  }
  f2.close();
  Serial.printf("\ndone writing\n");

  if ( !client.connect(server, 9900) ) {    
    Serial.println("failed (no connection to port 9900)!");
    WiFi.disconnect();
    return false;
  }
  timeout = 100;
  while(!client.available()) { delay(100); timeout--; if (timeout <= 0) {stopHostMode(); return false; } }
  while(client.available()) {
    size_t len = client.readBytes(md5Inc, 16);  
    Serial.printf("receiving %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", md5Inc[0],md5Inc[1],md5Inc[2],md5Inc[3],md5Inc[4],md5Inc[5],md5Inc[6],md5Inc[7],md5Inc[8],md5Inc[9],md5Inc[10],md5Inc[11],md5Inc[12],md5Inc[13],md5Inc[14],md5Inc[15]);  
  }
  delay(1000);
  
  //check
  uint8_t bufmd5[16];
  File f = SPIFFS.open("/fw.bin", "r");   
  if (f) {
    if (f.seek(0, SeekSet)) {
      MD5Builder md5;
      md5.begin();
      md5.addStream(f, f.size());
      md5.calculate();
      md5.getBytes(bufmd5);
    } 
    f.close();
  }
  Serial.printf("local %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", bufmd5[0],bufmd5[1],bufmd5[2],bufmd5[3],bufmd5[4],bufmd5[5],bufmd5[6],bufmd5[7],bufmd5[8],bufmd5[9],bufmd5[10],bufmd5[11],md5Inc[12],bufmd5[13],bufmd5[14],bufmd5[15]);

  if(md5Inc[0] != bufmd5[0] || md5Inc[1] != bufmd5[1])
  {
    Serial.printf("md5[0]/md5[1] not equal! %02x %02x - %02x %02x\n", md5Inc[0], bufmd5[0], md5Inc[1], bufmd5[1]);
    return false;
  }
    
  Serial.println("ready to flash!");
  return true;
}

void goToHostMode(uint32_t otaClient)
{
  timer.setTimer(100000, stopHostMode, 1);
  wifi_promiscuous_enable(0);
  IPAddress ip(192,168,0,1);
  IPAddress gateway(192,168,0,1);
  IPAddress subnet(255,255,255,0); 
  WiFi.softAPConfig(ip, gateway, subnet);
  WiFi.mode(WIFI_AP);
  const char* ap = (String("OTA_Update_") + String(ESP.getChipId())).c_str();
  const char* pw = (String("OTA_Update_") + String(otaClient)).c_str();
  Serial.printf ("Host AP: %s - Host PW: %s\n", ap, pw);
  WiFi.softAP(ap, pw);

  server.begin();
  int timeout = 100;
  while(!server.hasClient()) { delay(100); timeout--; if (timeout <= 0) {stopHostMode(); return; } }
  if (server.hasClient())
  {
    delay(1);    
    WiFiClient serverClient = server.available();

    File f = SPIFFS.open("/fw.bin", "r");   
    if (!f) {
      Serial.println("file not found (fw.bin)");
      return;
    }

    Serial.println("transfer bin");
    char buf[1024];
    int siz = f.size();
    while(siz > 0) {
      size_t len = std::min((int)(sizeof(buf) - 1), siz);
      f.read((uint8_t *)buf, len);
      serverClient.write((const char*)buf, len);
      siz -= len;
      yield();    
    }
    f.close();
    Serial.println("binary send");
    delay(1000);    
    serverClient.stop();
  }

  timeout = 100;
  while(!server.hasClient()) { delay(100); timeout--; if (timeout <= 0) {stopHostMode(); return; } }
  if (server.hasClient())
  {
    delay(1);    
    WiFiClient serverClient = server.available();

    Serial.println("md5 calc");
    File f = SPIFFS.open("/fw.bin", "r");   
    if (f.seek(0, SeekSet)) {
      MD5Builder md5;
      md5.begin();
      md5.addStream(f, f.size());
      md5.calculate();
      //server.send(200, "text/plain", md5.toString());  
      uint8_t bufmd5[16];
      md5.getBytes(bufmd5);
      serverClient.write((const char*)bufmd5, 16);      
      Serial.printf("sending %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", bufmd5[0],bufmd5[1],bufmd5[2],bufmd5[3],bufmd5[4],bufmd5[5],bufmd5[6],bufmd5[7],bufmd5[8],bufmd5[9],bufmd5[10],bufmd5[11],bufmd5[12],bufmd5[13],bufmd5[14],bufmd5[15]);
    } 

    Serial.println("binary send");
    delay(1000);    
    serverClient.stop();
  }
  stopHostMode();
}

void stopHostMode()
{
  Serial.println("time is up! stop host mode");
  server.stop();
  Serial.println("HTTP server stopped");
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA); 
  Serial.println("softAPdisconnect -> WIFI_STA");
  wifi_promiscuous_enable(1);
}

void resetRequestedUpdate()
{
  Serial.println("got no update :(");    
  requestedUpdate = false;
}

void processData(struct sniffer_buf2 *sniffer)
{
  msgData msg;
  msg.dst = (sniffer->buf[6]  << 24) | (sniffer->buf[7]  << 16) | (sniffer->buf[8]  << 8) | sniffer->buf[9];
  msg.src = (sniffer->buf[12] << 24) | (sniffer->buf[13] << 16) | (sniffer->buf[14] << 8) | sniffer->buf[15];
  msg.tns = (sniffer->buf[18] << 24) | (sniffer->buf[19] << 16) | (sniffer->buf[20] << 8) | sniffer->buf[21];
  msg.seq = (sniffer->buf[22] << 8) | sniffer->buf[23];
  msg.ver = sniffer->buf[42];
  msg.ttl = sniffer->buf[43];
  msg.type = sniffer->buf[44];
  msg.dataLength = (sniffer->buf[39])-5;
  memcpy(msg.data, &(sniffer->buf[45]), sniffer->buf[39]-5);
  
  Serial.printf("Data (dst: %02x:%02x:%02x:%02x:%02x:%02x (%d), src: %02x:%02x:%02x:%02x:%02x:%02x (%d), rssi: %d, ttl: %d, type: %d, seq: %d: ", sniffer->buf[4], sniffer->buf[5], sniffer->buf[6], sniffer->buf[7], sniffer->buf[8], sniffer->buf[9], msg.dst, sniffer->buf[10], sniffer->buf[11], sniffer->buf[12], sniffer->buf[13], sniffer->buf[14], sniffer->buf[15], msg.src, sniffer->rx_ctrl.rssi, msg.ttl, msg.type, msg.seq);
  for(int i = 0; i < msg.dataLength; i++)
    Serial.printf("%02x ", msg.data[i]);
  Serial.printf("\n"); 

  if(lastSeqNum[msg.src] == msg.seq)
  {
    Serial.printf("No new seq num :(\n");    
    return;
  }
  lastSeqNum[msg.src] = msg.seq;

  
  if(msg.type == MSG_Data) //standard data msg
  {
    if(msg.dst == ESP.getChipId())
    {
      //i am the reciever! yaaaaaay
      Serial.printf("I am the dst (dst(%d) == chipid(%d))!\n", msg.dst, ESP.getChipId());      
    }
    else
    {
      if(msg.ttl > 0 && msg.ttl < START_TTL+1) //not
      {
        //forward!
        int wait = 500+random(2500);
        delayMicroseconds(wait);
        Serial.printf("Forward to dst(%d) from me(%d) with new ttl:%d after %d us!\n", msg.dst, ESP.getChipId(), (msg.ttl-1), wait);
        forwardPacket(sniffer->buf);
        int res = wifi_send_pkt_freedom(sniffer->buf, sizeof(beacon_raw)+ msg.dataLength, 0);
      }
    }
  }
  else if(msg.type == MSG_RequestOTA && msg.dst == ESP.getChipId()) //req. OTA 
  {
    //src wants to get a OTA
    //stop beacons, stop promisc_cb, go STA, wait for connect, 
    Serial.println("someone wants an update :)");
    delay(1000);
    Serial.println("send MSG_AcceptOTA");
    uint8_t result[sizeof(beacon_raw)];
    createPacket(result, {}, 0, msg.src, MSG_AcceptOTA);
    int res = wifi_send_pkt_freedom(result, sizeof(beacon_raw), 0); 
    goToHostMode(msg.src);
  }
  else if(msg.type == MSG_AcceptOTA && msg.dst == ESP.getChipId() && requestedUpdate) //accept OTA-request
  {
    Serial.println("whoohoo, we get updated!");
    if(goToRequestMode(msg.src))
      flashFirmware();
    else
      Serial.println("  ...not (error) :(");
  }
  else
  {
    if(msg.type != MSG_KeepAlive)
      Serial.println("Unknown/Unwanted Messagetype");
  }

  
  if(msg.ver > VERSION && !requestedUpdate)
  {
    Serial.println("there is a new version out there! fuck the rest, gimmegimme!");
    requestedUpdate = true;
    timer.setTimer(20000, resetRequestedUpdate, 1);
    uint8_t result[sizeof(beacon_raw)];
    createPacket(result, {}, 0, msg.src, MSG_RequestOTA);
    int res = wifi_send_pkt_freedom(result, sizeof(beacon_raw), 0);
    Serial.printf("waiting for response (%d)\n", inProcess);
  }
}

void promisc_cb(uint8_t *buf, uint16_t len)
{
  noInterrupts();
  if (len == 128 && !inProcess){
    inProcess = true;  
    sniffer = (struct sniffer_buf2*) buf;
    if (sniffer->buf[0] == 0x80 /*beacon*/&& sniffer->buf[37] == 0x00 /*hidden ssid*/&& sniffer->buf[38] == 0xDD /*vendor info*/&& sniffer->buf[4] == 0xef /*magic word1*/&& sniffer->buf[5] == 0x50/*magic word2*/)
    {
      //dont process data here in interrupt  
      //buffer is called from main routine  
    }
    else
    {
      inProcess = false; 
    }
  }
  interrupts();
}

void send()
{
  uint8_t result[sizeof(beacon_raw)];
  createPacket(result, {}, 0, 0xffffffff, MSG_KeepAlive);
  int res = wifi_send_pkt_freedom(result, sizeof(result), 0);
  Serial.printf("sending (seqnum: %d, res: %d)\n", seqnum, res);
}

void setupFreedom()
{
  WiFi.mode(WIFI_STA); 
  wifi_set_channel(CHANNEL);
  wifi_set_phy_mode(PHY_MODE_11B);
  
  wifi_promiscuous_enable(0);
  // Set up promiscuous callback
  wifi_set_promiscuous_rx_cb(promisc_cb);
  wifi_promiscuous_enable(1);
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  //setupIdeOta();
  //timer.setTimer(100000, setupFreedom, 1);
  setupFreedom();
  
  pinMode(2, OUTPUT);
  digitalWrite(2, HIGH);

  SPIFFS.begin();
  
  // Promiscuous works only with station mode
  seqnum = ESP.getChipId() & 0xfff; //semi-rnd init
  
  Serial.printf("\n\nSDK version:%s - chipId: %d - Firmware version: %d\n", system_get_sdk_version(), ESP.getChipId(), VERSION);
  
  timer.setInterval(10000, send);  
}


void loop() { 
  delay(1);
  ArduinoOTA.handle();
  timer.run();

  if(inProcess)
  {
    processData(sniffer);
    inProcess = false;
  }
  
  if (Serial.available()) {          // got anything from Linux?        
    char c = (char)Serial.read();    // read from Linux  

    if(c == 's')
    {
      uint8_t result[sizeof(beacon_raw)];
      createPacket(result, {}, 0, 0, MSG_Unknown);
      int res = wifi_send_pkt_freedom(result, sizeof(beacon_raw), 0);
      Serial.printf("sending (seqnum: %d, res: %d)\n", seqnum, res);
    }
    if(c == 'x')
    {
      Serial.printf("reboot\n");
      delay(100);
      ESP.restart();
    }
    if(c == 'w')
    {      
      File f = SPIFFS.open("/f.txt", "w");
      if (!f) {
          Serial.println("file open failed");
      }
      Serial.println("====== Writing to SPIFFS file =========");
      // write 10 strings to file
      for (int i=1; i<=10; i++){
        f.print("Millis() : ");
        f.println(millis());
        Serial.println(millis());
      }
      f.close();
      
    }
    if(c == 'v')
    {      
      Serial.println("======        Version         =========");
      Serial.print("Version: ");
      Serial.println(VERSION);
      Serial.println("Compiled: " __DATE__ " " __TIME__ ", Complier-Version:" __VERSION__);
      Serial.printf("Stations connected = %d\n", WiFi.softAPgetStationNum());
    }
    if(c == 'h')
    {      
      Serial.println("======       HOST MODE        =========");
      goToHostMode(0);
    }
    if(c == 'q')
    {      
      Serial.println("======      REQUEST MODE      =========");
      goToRequestMode(0);
    }
    if(c == 'e')
    {      
      wifi_promiscuous_enable(1);
    }
    if(c == 'r')
    {      
      File f = SPIFFS.open("/f.txt", "r");
      if (!f) {
          Serial.println("file open failed");
      } 
      else
      {
        Serial.println("====== Reading from SPIFFS file =======");
        // write 10 strings to file
        for (int i=1; i<=10; i++){
          String s=f.readStringUntil('\n');
          Serial.print(i);
          Serial.print(":");
          Serial.println(s);
        }
      }
      f.close();
    }
    if(c == '5')
    {      
      File f = SPIFFS.open("/md5", "r");
      if (!f) {
          Serial.println("file open failed");
      } 
      else
      {
        Serial.println("====== Reading from SPIFFS file =======");
        // write 10 strings to file
        String s=f.readStringUntil('\n');
        Serial.println(s);        
      }
      f.close();
    }
    if(c == 'f')
    {      
      Serial.println("======       FLASHING FW        =======");
      flashFirmware();
    }
    if(c == 'd')
    {
      Serial.println("======== Getting flash info ==========");
      uint32_t realSize = ESP.getFlashChipRealSize();
      uint32_t ideSize = ESP.getFlashChipSize();
      FlashMode_t ideMode = ESP.getFlashChipMode();
  
      Serial.printf("Flash real id:   %08X\n", ESP.getFlashChipId());
      Serial.printf("Flash real size: %u\n\n", realSize);
  
      Serial.printf("Flash ide size:  %u\n", ideSize);
      Serial.printf("Flash ide speed: %u\n", ESP.getFlashChipSpeed());
      Serial.printf("Flash ide mode:  %s\n", (ideMode == FM_QIO ? "QIO" : ideMode == FM_QOUT ? "QOUT" : ideMode == FM_DIO ? "DIO" : ideMode == FM_DOUT ? "DOUT" : "UNKNOWN"));
  
      if(ideSize != realSize) {
          Serial.println("Flash Chip configuration wrong!\n");
      } else {
          Serial.println("Flash Chip configuration ok.\n");
      }

      
      Serial.println("======       IP ADDRESS        ========");
      Serial.println(WiFi.localIP());
      Serial.println("====== Getting filesystem info ========");
      Serial.print("ESP.getFreeSketchSpace(): ");
      Serial.println(ESP.getFreeSketchSpace());
      FSInfo fs_info;
      SPIFFS.info(fs_info);      
      Serial.printf("totalBytes %d, usedBytes %d, blockSize %d, pageSize %d, maxOpenFiles %d, maxPathLength %d", fs_info.totalBytes, fs_info.usedBytes, fs_info.blockSize, fs_info.pageSize, fs_info.maxOpenFiles, fs_info.maxPathLength);
      Serial.print("\n");
      Serial.println("====== Reading from SPIFFS root =======");
      Dir dir = SPIFFS.openDir("/");
      while (dir.next()) {
          Serial.print(dir.fileName());
          Serial.print(" - ");
          File f = dir.openFile("r");
          Serial.print(f.size());

          if (f.seek(0, SeekSet)) {
            MD5Builder md5;
            md5.begin();
            md5.addStream(f, f.size());
            md5.calculate();
            Serial.print("bytes - md5:");
            Serial.println( md5.toString());
          }
          f.close();
      }
    }
  }
}
