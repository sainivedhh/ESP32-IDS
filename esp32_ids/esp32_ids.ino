#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>

const char* WIFI_SSID = "Saie";
const char* WIFI_PASS = "sunshine";

#define LED_TCP    2
#define LED_HTTP   4
#define LED_MQTT   5
#define ALPHABET_SIZE 15
#define MAX_STATES    10
#define NUM_DFA        3
#define TRAP_STATE     9

const char* dfaName[NUM_DFA]  = { "TCP",  "HTTP",  "MQTT"  };
const char* severity[NUM_DFA] = { "CRITICAL", "HIGH", "MEDIUM" };
int ledPins[NUM_DFA] = { LED_TCP, LED_HTTP, LED_MQTT };

int TCP_TABLE[MAX_STATES][ALPHABET_SIZE] = {
  {1,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {6,2,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,3,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,4,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,5},
  {0,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {6,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}
};

int HTTP_TABLE[MAX_STATES][ALPHABET_SIZE] = {
  {9,9,9,9,9,1,2,7,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,4,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,3,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,4,9,9,9,9,9},
  {9,9,9,9,9,1,2,7,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,7,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}
};

int MQTT_TABLE[MAX_STATES][ALPHABET_SIZE] = {
  {9,9,9,9,9,9,9,9,9,9,1,9,8,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,2,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,3,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,4,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,5},
  {9,9,9,9,9,9,9,9,9,9,1,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,8,9,9},
  {9,9,9,9,9,9,9,9,9,9,9,9,9,9,9}
};

int curState[NUM_DFA] = {0, 0, 0};
int (*tables[NUM_DFA])[ALPHABET_SIZE] = { TCP_TABLE, HTTP_TABLE, MQTT_TABLE };
int acceptStates[NUM_DFA] = {6, 7, 8};

struct LEDJob {
  bool active=false; int pin=0; int total=0; int done=0;
  bool on=false; uint32_t last=0; uint16_t interval=150;
};
LEDJob ledJobs[NUM_DFA];

void startBlink(int idx, int times, uint16_t ms=150) {
  LEDJob& j=ledJobs[idx];
  j.active=true; j.pin=ledPins[idx]; j.total=times*2;
  j.done=0; j.on=false; j.last=millis(); j.interval=ms;
  digitalWrite(j.pin, LOW);
}

void tickLEDs() {
  uint32_t now=millis();
  for(int i=0;i<NUM_DFA;i++){
    LEDJob& j=ledJobs[i];
    if(!j.active) continue;
    if(now-j.last<j.interval) continue;
    j.last=now; j.on=!j.on;
    digitalWrite(j.pin, j.on?HIGH:LOW);
    j.done++;
    if(j.done>=j.total){ j.active=false; digitalWrite(j.pin,HIGH); }
  }
}

struct SymbolEntry { const char* name; int sym; };
SymbolEntry symbolMap[] = {
  {"TCP_SYN",0},{"TCP_SYNACK",1},{"TCP_ACK",2},{"TCP_FIN",3},{"TCP_RST",4},
  {"HTTP_GET",5},{"HTTP_POST",6},{"HTTP_DELETE",7},{"HTTP_AUTH",8},{"HTTP_RESP",9},
  {"MQTT_CONNECT",10},{"MQTT_CONNACK",11},{"MQTT_PUBLISH",12},{"MQTT_PUBACK",13},{"MQTT_DISC",14}
};

int mapSymbol(String s){
  s.trim();
  for(int i=0;i<15;i++) if(s==symbolMap[i].name) return symbolMap[i].sym;
  return -1;
}

#define LOG_MAX 60
String logBuf[LOG_MAX];
int logHead=0, logCount=0;

void addLog(String msg){
  logBuf[logHead]=msg;
  logHead=(logHead+1)%LOG_MAX;
  if(logCount<LOG_MAX) logCount++;
  Serial.println(msg);
}

WebServer server(80);

void addCORS(){
  server.sendHeader("Access-Control-Allow-Origin","*");
  server.sendHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers","Content-Type");
}

void handleSend(){
  addCORS();
  if(!server.hasArg("event")){ server.send(400,"application/json","{\"error\":\"missing event\"}"); return; }
  String evName=server.arg("event");
  int sym=mapSymbol(evName);
  if(sym==-1){ 
    Serial.println("[ERR] Unknown event: " + evName);
    server.send(400,"application/json","{\"error\":\"unknown event\"}"); 
    return; 
  }

  // Each protocol has exactly 5 symbols (TCP:0-4, HTTP:5-9, MQTT:10-14)
  int ownerID = sym / 5;
  Serial.print("[SYS] Received Event: " + evName + " (sym " + String(sym) + ")");
  Serial.println(" -> Target Protocol Index: " + String(ownerID));

  String json="{\"event\":\""+evName+"\",\"results\":[";

  for(int i=0;i<NUM_DFA;i++){
    int prev=curState[i];
    int next=prev; 
    String status="ok";

    // ABSOLUTE ISOLATION: Only process if the event name belongs to this specific DFA
    bool isOwner = false;
    if (i == 0 && evName.startsWith("TCP_")) isOwner = true;
    else if (i == 1 && evName.startsWith("HTTP_")) isOwner = true;
    else if (i == 2 && evName.startsWith("MQTT_")) isOwner = true;

    if(isOwner) {
      next=tables[i][prev][sym];
      Serial.println("  [DFA-" + String(dfaName[i]) + "] Processing Owned Event: " + evName);

      if(next==TRAP_STATE && prev!=TRAP_STATE){
        curState[i]=next;
        status="violation";
        startBlink(i,3,200);
        addLog("[!] "+evName+" -> "+String(dfaName[i])+" PROTOCOL VIOLATION");
      } else if(next==acceptStates[i]){
        curState[i]=next;
        status="intrusion";
        startBlink(i,5,120);
        addLog("[!!!] "+evName+" -> "+String(dfaName[i])+" INTRUSION ("+String(severity[i])+")");
      } else if(next==TRAP_STATE && prev==TRAP_STATE){
        status="ok";
      } else {
        curState[i]=next;
        if(prev!=next) addLog("[ ] "+evName+" -> "+String(dfaName[i])+" q"+prev+"->q"+next);
      }
    } else {
        // Explicitly ensuring no log or state change for non-owners
    }

    if(i>0) json+=",";
    json+="{\"dfa\":\""+String(dfaName[i])+"\""
         +",\"severity\":\""+String(severity[i])+"\""
         +",\"from\":"+prev
         +",\"to\":"+next
         +",\"status\":\""+status+"\""
         +"}";
  }

  json+="]}";
  server.send(200,"application/json",json);
}

void handleReset(){
  addCORS();
  for(int i=0;i<NUM_DFA;i++){
    curState[i]=0;
    ledJobs[i].active=false;
    digitalWrite(ledPins[i],LOW);
  }
  addLog("[RESET] All DFAs reset to q0");
  server.send(200,"application/json","{\"status\":\"reset ok\"}");
}

void handleState(){
  addCORS();
  String json="{\"states\":[";
  for(int i=0;i<NUM_DFA;i++){
    if(i>0) json+=",";
    json+="{\"dfa\":\""+String(dfaName[i])+"\",\"state\":"+curState[i]+"}";
  }
  json+="]}";
  server.send(200,"application/json",json);
}

void handleLog(){
  addCORS();
  String json="{\"log\":[";
  int start=(logHead-logCount+LOG_MAX)%LOG_MAX;
  for(int k=0;k<logCount;k++){
    int idx=(start+k)%LOG_MAX;
    if(k>0) json+=",";
    String line=logBuf[idx];
    line.replace("\"","\\\"");
    json+="\""+line+"\"";
  }
  json+="]}";
  server.send(200,"application/json",json);
}

void handleOptions(){ addCORS(); server.send(204); }

void setup(){
  Serial.begin(115200);
  pinMode(LED_TCP,OUTPUT); digitalWrite(LED_TCP,LOW);
  pinMode(LED_HTTP,OUTPUT); digitalWrite(LED_HTTP,LOW);
  pinMode(LED_MQTT,OUTPUT); digitalWrite(LED_MQTT,LOW);

  Serial.println("\n=== ESP32 DFA-IDS ===");
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID,WIFI_PASS);
  int tries=0;
  while(WiFi.status()!=WL_CONNECTED && tries<30){ delay(500); Serial.print("."); tries++; }
  if(WiFi.status()==WL_CONNECTED){
    Serial.println("\nWiFi connected!");
    Serial.print("IP: "); Serial.println(WiFi.localIP());
    addLog("[BOOT] IDS online at "+WiFi.localIP().toString());
  } else {
    Serial.println("\nWiFi FAILED");
  }

  server.on("/send",HTTP_GET,handleSend);
  server.on("/reset",HTTP_GET,handleReset);
  server.on("/state",HTTP_GET,handleState);
  server.on("/log",HTTP_GET,handleLog);
  server.on("/send",HTTP_OPTIONS,handleOptions);
  server.on("/reset",HTTP_OPTIONS,handleOptions);
  server.on("/state",HTTP_OPTIONS,handleOptions);
  server.on("/log",HTTP_OPTIONS,handleOptions);
  server.begin();
  Serial.println("Server started. Open IP in browser.");
}

void loop(){
  server.handleClient();
  tickLEDs();
}
