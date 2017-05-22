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

#define TIMEOUT_HOST 60
#define TIMEOUT_REQUEST 20
#define KEEPALIVE_INTERVAL 20
#define CHANNEL 1

#include "FS.h"
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <SimpleTimer.h>
#include <map>
#include <WiFiUdp.h>
#include <time.h>
#include "defines.h"

WiFiClient client;
WiFiServer server(9900);

char IspSsid[] = "ssvl_dev";  
char IspPass[] = "winchester";

const char* ntpServerName = "time.nist.gov";
byte ntpPacketBuffer[48];
IPAddress timeServerIP;
WiFiUDP udp;

time_t timestamp = 0;

uint16_t waitForAck = 0;

SimpleTimer timer;
int updateModeTimer;
bool inUpdateMode = false;
int requestUpdateTimer;
bool requestedUpdate = false;
int inUpdateTimeoutTimer;
int ntpUpdateTimer;
int ackTimer;

bool inProcess = false;
int ledState;

struct sniffer_buf2 *sniffer;

uint16_t seqnum = 0x000;
std::map<uint32_t,uint16_t> lastSeqNum;

static inline uint32_t intDisable()
{
    return xt_rsil(15);
    
}
static inline void intEnable(uint32_t state)
{
    xt_wsr_ps(state);
}

uint16_t createPacket(uint8_t* result, uint8_t *buf, uint16_t len, uint32_t dst, uint8_t type)
{
  memcpy(&result[0], &beacon_raw[0], sizeof(beacon_raw));
  memcpy(&result[sizeof(beacon_raw)], &buf[0], len);

  //dst
  result[4 + 2] = (dst >> 24) & 0xFF;
  result[4 + 3] = (dst >> 16) & 0xFF;
  result[4 + 4] = (dst >> 8) & 0xFF;
  result[4 + 5] = (dst) & 0xFF;

  //src
  result[10 + 2] = (ESP.getChipId() >> 24) & 0xFF;
  result[10 + 3] = (ESP.getChipId() >> 16) & 0xFF;
  result[10 + 4] = (ESP.getChipId() >> 8) & 0xFF;
  result[10 + 5] = (ESP.getChipId()) & 0xFF;

  //transmitc
  result[16 + 2] = (ESP.getChipId() >> 24) & 0xFF;
  result[16 + 3] = (ESP.getChipId() >> 16) & 0xFF;
  result[16 + 4] = (ESP.getChipId() >> 8) & 0xFF;
  result[16 + 5] = (ESP.getChipId()) & 0xFF;

  result[22] = (seqnum & 0x0f) << 4;
  result[23] = (seqnum & 0xff0) >> 4;

  uint16_t seqTmp = seqnum;
  seqnum++;
  if (seqnum > 0xfff)
    seqnum = 1;

  result[39] += len;
  result[42] = VERSION;
  result[43] = START_TTL;
  result[44] = type;

  return seqTmp;
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

void sendNTPpacket()
{
  if(inUpdateMode) return;
  WiFi.hostByName(ntpServerName, timeServerIP); 
  Serial.println("sending NTP packet...");
  // set all bytes in the buffer to 0
  memset(ntpPacketBuffer, 0, 48);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  ntpPacketBuffer[0] = 0b11100011;   // LI, Version, Mode
  ntpPacketBuffer[1] = 0;     // Stratum, or type of clock
  ntpPacketBuffer[2] = 6;     // Polling Interval
  ntpPacketBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  ntpPacketBuffer[12]  = 49;
  ntpPacketBuffer[13]  = 0x4E;
  ntpPacketBuffer[14]  = 49;
  ntpPacketBuffer[15]  = 52;

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  udp.beginPacket(timeServerIP, 123); //NTP requests are to port 123
  udp.write(ntpPacketBuffer, 48);
  udp.endPacket();

  int timeout = 20;
  while(timeout > 0)
  {
    int cb = udp.parsePacket();

    if (cb > 0) {
      Serial.print("ntp packet received, length=");
      Serial.println(cb);
      // We've received a packet, read the data from it
      udp.read(ntpPacketBuffer, 48); // read the packet into the buffer
  
      //the timestamp starts at byte 40 of the received packet and is four bytes,
      // or two words, long. First, esxtract the two words:
  
      unsigned long highWord = word(ntpPacketBuffer[40], ntpPacketBuffer[41]);
      unsigned long lowWord = word(ntpPacketBuffer[42], ntpPacketBuffer[43]);
      // combine the four bytes (two words) into a long integer
      // this is NTP time (seconds since Jan 1 1900):
      unsigned long secsSince1900 = highWord << 16 | lowWord;
  
      // Unix time starts on Jan 1 1970. In seconds, that's 2208988800:
      const unsigned long seventyYears = 2208988800UL;
      // subtract seventy years:
      unsigned long epoch = secsSince1900 - seventyYears;

      struct tm  ts;
      ts = *localtime((time_t*)&epoch);      
      Serial.printf ("Current local time and date: %s\n", asctime(&ts));
      return;
    }
    timeout--;
    delay(1000);
  }
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
  while(!client.available()) {delay(1); timer.run();}
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
  while(!client.available()) {delay(1); timer.run();}
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

  if(memcmp(md5Inc, bufmd5, 16))
  {
    Serial.printf("md5 not equal!\n");
  }
  else
  {
    Serial.println("ready to flash!");
    flashFirmware();
  }
  
  return true;
}

void goToHostMode(uint32_t otaClient)
{
  inUpdateMode = true;
  updateModeTimer = timer.setInterval(TIMEOUT_HOST * 1000, stopHostMode);
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
  while(!server.hasClient()) {delay(1); timer.run();}
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
  
  while(!server.hasClient()) {delay(1); timer.run();}
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
  inUpdateMode = false;
  timer.disable(updateModeTimer);
}

void resetRequestedUpdate()
{
  Serial.println("got no update :(");    
  requestedUpdate = false;
  timer.disable(requestUpdateTimer);
}

void processData(struct sniffer_buf2 *sniffer)
{
  if(sniffer->buf[4] != 0xef || sniffer->buf[5] != 0x50) return;
  msgData msg;
  msg.dst = (sniffer->buf[6]  << 24) | (sniffer->buf[7]  << 16) | (sniffer->buf[8]  << 8) | sniffer->buf[9];
  msg.src = (sniffer->buf[12] << 24) | (sniffer->buf[13] << 16) | (sniffer->buf[14] << 8) | sniffer->buf[15];
  msg.trs = (sniffer->buf[18] << 24) | (sniffer->buf[19] << 16) | (sniffer->buf[20] << 8) | sniffer->buf[21];
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

  
  if(msg.type == MSG_Data || msg.type == MSG_Data_Ack) //standard data msg
  {
    if(msg.dst == ESP.getChipId() && msg.type == MSG_Data)
    {
      //i am the reciever! yaaaaaay
      Serial.printf("I am the dst (dst(%d) == chipid(%d))! Sending ack...\n", msg.dst, ESP.getChipId());     
      
      //send reply
      uint8_t result[sizeof(beacon_raw) + 2];      
      uint8_t data[8] = {sniffer->buf[22], sniffer->buf[23]}; //ack with msg.src & msg.seq
      createPacket(result, data, 2, msg.src, MSG_Data_Ack);
      int res = wifi_send_pkt_freedom(result, sizeof(result), 0); 
    }
    else if(msg.dst == ESP.getChipId() && msg.type == MSG_Data_Ack)
    {      
      uint16_t ackSeq = (sniffer->buf[22] << 8) | sniffer->buf[23];
      if(ackSeq == waitForAck)
      {
        Serial.printf("Got ack for %d\n", ackSeq));
        waitForAck = 0;
        timer.disable(ackTimer);
      }
    }
    else
    {
      if(msg.ttl > 0 && msg.ttl < START_TTL+1) //not
      {
        delayMicroseconds(2000+random(6000)); //2-8ms delay to avoid parallel-fwd of multiple nodes
        //forward!
        Serial.printf("Forward to dst(%d) from me(%d) with new ttl:%d!\n", msg.dst, ESP.getChipId(), (msg.ttl-1));
        forwardPacket(sniffer->buf);
        int res = wifi_send_pkt_freedom(sniffer->buf, sizeof(beacon_raw)+ msg.dataLength, 0);
      }
    }
  }
  else if(msg.type == MSG_RequestOTA && msg.dst == ESP.getChipId() && !inUpdateMode) //req. OTA 
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
  else if(msg.type == MSG_AcceptOTA && msg.dst == ESP.getChipId() && !inUpdateMode && requestedUpdate) //accept OTA-request
  {
    Serial.println("whoohoo, we get updated!");
    goToRequestMode(msg.src);
  }
  else if(msg.type == MSG_KeepAlive)
  {}
  else
  {
    Serial.println("Unknown/Unwanted Messagetype");
  }

  
  if(msg.ver > VERSION && !requestedUpdate)
  {
    Serial.println("there is a new version out there! fuck the rest, gimmegimme!");
    requestedUpdate = true;
    requestUpdateTimer = timer.setInterval(TIMEOUT_REQUEST * 1000, resetRequestedUpdate);
    uint8_t result[sizeof(beacon_raw)];
    createPacket(result, {}, 0, msg.src, MSG_RequestOTA);
    int res = wifi_send_pkt_freedom(result, sizeof(beacon_raw), 0);
    Serial.printf("waiting for response (%d)\n", inProcess);
  }
}

void ICACHE_RAM_ATTR promisc_cb(uint8_t *buf, uint16_t len)
{
  uint32_t old_ints = intDisable();
  if (len == 128 && buf[12+4] == 0xef && !inProcess ){
    inProcess = true;  
    sniffer = (struct sniffer_buf2*) buf;
    if (sniffer->buf[0] == 0x80 /*beacon*/&& sniffer->buf[37] == 0x00 /*hidden ssid*/&& sniffer->buf[38] == 0xDD /*vendor info*/&& sniffer->buf[4] == 0xef /*magic word1*/&& sniffer->buf[5] == 0x50/*magic word2*/)
    {
      //dont process data here in interrupt  
    }
    else
    {
      inProcess = false; 
    }
  }
  intEnable(old_ints);
}

void resendMsg()
{
  int res = wifi_send_pkt_freedom(sendBuffer, sendBufferLength, 0);
  waitForAck = seq;
  Serial.printf("re-sending data (seqnum: %d, res: %d, len %d) to &d\n", seq, res, length, destination);
  
  ackTimer = timer.setTimer(100, resendMsg, 1);
}

uint8_t* sendBuffer;
size_t sendBufferLength;

void sendDataMsg(uint8_t data, size_t length, uint32_t destination)
{
  if(inUpdateMode) return;
  uint8_t result[sizeof(beacon_raw)+length];
  uint16_t seq = createPacket(result, data, length, destination, MSG_Data);
  int res = wifi_send_pkt_freedom(result, sizeof(result), 0);
  waitForAck = seq;
  Serial.printf("sending data (seqnum: %d, res: %d, len %d) to &d\n", seq, res, length, destination);
  
  sendBuffer = result;
  sendBufferLength = sizeof(beacon_raw)+length;
  ackTimer = timer.setTimer(100, resendMsg, 1);
}

void sendKeepAlive()
{
  if(inUpdateMode) return;
  uint8_t result[sizeof(beacon_raw)];
  uint16_t seq = createPacket(result, {}, 0, 0xffffffff, MSG_KeepAlive);
  int res = wifi_send_pkt_freedom(result, sizeof(result), 0);
  Serial.printf("sending KeepAlive (seqnum: %d, res: %d)\n", seq, res);
}


void setupIsp()
{
  Serial.print("Connecting to ISP ");
  Serial.println(IspSsid);
  WiFi.begin(IspSsid, IspPass);

  uint8_t timeout = 10;
  while (WiFi.status() != WL_CONNECTED && timeout > 0) {
    delay(500);
    Serial.print(".");
    timeout--;
  }
  Serial.println("");
  if(timeout == 0)
  {
    Serial.println("No connection to ISP");
  }
  else
  {  
    Serial.println("WiFi connected to ISP");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
  
    Serial.println("Starting UDP");
    udp.begin(2390);
    Serial.print("Local port: ");
    Serial.println(udp.localPort());
    sendNTPpacket();
    udp.stop();
  }
  setupFreedom();
}

void setupFreedom()
{
  Serial.println("Setting up Freedom Mode");
  udp.stop();
  WiFi.mode(WIFI_STA); 
  wifi_set_channel(CHANNEL);
  wifi_set_phy_mode(PHY_MODE_11B);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promisc_cb);
  wifi_promiscuous_enable(1);
}

void setup() {
  
  Serial.begin(115200);
  delay(2000);
  Serial.printf("\n\nSDK version: %s - chipId: %d - fw-version: %d\n", system_get_sdk_version(), ESP.getChipId(), VERSION);
  pinMode(2, OUTPUT);
  digitalWrite(2, LOW);
  SPIFFS.begin();
  
  // Promiscuous works only with station mode
  seqnum = ESP.getChipId() & 0xfff; //semi-rnd init
  
  WiFi.mode(WIFI_STA); 
  setupIsp();
  setupFreedom();
      
  //timer.setInterval(21600 * 1000 /* = 6 Stunden*/, setupIsp);
  timer.setInterval(KEEPALIVE_INTERVAL * 1000, sendKeepAlive);
}

unsigned long previousMillis = 0;        // will store last time LED was updated
void loop() {   
  unsigned long currentMillis = millis();
  if (currentMillis - previousMillis >= 3000) {
    // save the last time you blinked the LED
    previousMillis = currentMillis;

    // if the LED is off turn it on and vice-versa:
    if (ledState == LOW) {
      ledState = HIGH;
    } else {
      ledState = LOW;
    }

    // set the LED with the ledState of the variable:
    digitalWrite(2, ledState);
  }
  
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
      sendKeepAlive();
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
