void connectToIdeHost()
{
  WiFi.mode(WIFI_STA);
  WiFi.begin("erwin21_EXT", "70069228");
  while (WiFi.waitForConnectResult() != WL_CONNECTED) {
    Serial.println("Connection to idleHost Failed!");
  }
}

void setupIdeOta()
{ 
  connectToIdeHost();
  ArduinoOTA.onStart([]() {
    String type;
    if (ArduinoOTA.getCommand() == U_FLASH)
      type = "sketch";
    else // U_SPIFFS
    {
      type = "filesystem";
      SPIFFS.end();
    }
    // NOTE: if updating SPIFFS this would be the place to unmount SPIFFS using SPIFFS.end()
  
    Serial.println(" IDE OTA - Start updating " + type);
  });

  ArduinoOTA.onEnd([]() {
    Serial.println("\nIDE OTA - END");
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf(" IDE OTA - Progress: %u%%\r", (progress / (total / 100)));
  });

  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf("Error[%u]: ", error);
    if (error == OTA_AUTH_ERROR) Serial.println(" IDE OTA - Auth Failed");
    else if (error == OTA_BEGIN_ERROR) Serial.println(" IDE OTA - Begin Failed");
    else if (error == OTA_CONNECT_ERROR) Serial.println(" IDE OTA - Connect Failed");
    else if (error == OTA_RECEIVE_ERROR) Serial.println(" IDE OTA - Receive Failed");
    else if (error == OTA_END_ERROR) Serial.println(" IDE OTA - End Failed");
  });
  ArduinoOTA.begin();
  Serial.println(" IDE OTA - Ready");
  Serial.print(" IDE OTA - IP address: ");
  Serial.println(WiFi.localIP());
}