/*
  xdrv_92_sip.ino - Fritzbox SIP client for Tasmota.

  Copyright (C) 2022  Günther Klement Version 1.0.12.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/******************************************************************************************************************************
 * You will need some hardware to detect door bell. I am using opto coupler to isolate from bell's ~ 9 Volt. 
 * AC power is used to supply ESP.
 * Maybe a microphone near to bell could detect as well (just an idea).
 * If door bell button press is detected this sip client will call DIAL_NR on fritzbox sip server. 
 * Using UDP to register sip client (tasmota) to fritz box. 
 * The transitions are as follow (Note: SIP_CODE_.. from fritzbox, SIP_STATE_.. own transition/action/state):
 * 
    SIP_STATE_INVITE -> SIP_CODE_UNAUTHORIZED -> SIP_STATE_ACK -> SIP_STATE_INVITE_401 -> SIP_CODE_TRYING -> SIP_CODE_PROGRESS
    - wait x-rings -> SIP_STATE_CANCEL -> SIP_CODE_REQUEST_CANCELLED -> SendAck -> SIP_STATE_CANCEL.
    - answer phone -> SIP_CODE_OK -> SipSendBye -> SIP_STATE_BYE -> after timeout -> SIP_STATE_IDLE.
    - SIP_CODE_DECLINED/SIP_CODE_PARTY_HANGS_UP -> SipSendAck
    - ERROR_STATE -> wait -> SIP_STATE_INIT.
******************************************************************************************************************************/

#ifdef USE_SIP
#define XDRV_92 92

#include <TasmotaSerial.h>
#include <inttypes.h>
#include <include/tasmota.h>
#include <WiFi.h>
#include <WifiUdp.h>

#define DIAL_NR                 "**614"             // **9 for all internal handsets. Change with sipset dial_nr=**614 and mem1 **614
#define DIAL_USER               "Haustür"           // Shows up as caller on phone
#define LOCAL_IP                "192.168.178.17"    // will be set automatically at startup
#define LOCAL_PORT              5060                // unlikely to be already used
#define SIP_FRITZBOX_IP         "192.168.178.1"     // to test enter your dev machine's ip and run Packet Sender
#define SIP_FRITZBOX_PORT       5060
#define SIP_FRITZBOX_USER       "tklingel"          // registered as new LAN/WLAN fritzbox IP-telefon and setup user registration
#define SIP_FRITZBOX_PASSWORD   "changeme"          // password configured on fritzbox. Use command sipset pwd=1234 and mem4.
#define PEERIP                  "fritz.box"         // also default 192.168.178.1 may be used
#define SHOW_EXTRA_INFO_SEC     240                 // more info for x seconds after reset

// states may trigger an action or sitting around waiting for sip code or timer event.
#define SIP_STATE_INIT          0
#define SIP_STATE_IDLE          1
#define SIP_STATE_ACK           2
#define SIP_STATE_CANCEL        3
#define SIP_STATE_BYE           4
#define SIP_STATE_OK            5
#define SIP_STATE_DO_RING       6
#define SIP_STATE_INVITE        7
#define SIP_STATE_INVITE_401    8
#define SIP_STATE_RINGING       9
// sip response codes
#define SIP_CODE_LISTENING      0
#define SIP_CODE_TRYING         100
#define SIP_CODE_RINGING        180
#define SIP_CODE_PROGRESS       183
#define SIP_CODE_OK             200
#define SIP_CODE_BAD_REQUEST    400
#define SIP_CODE_UNAUTHORIZED   401
#define SIP_CODE_REQUEST_CANCELLED 487
#define SIP_CODE_INVALID        500
#define SIP_CODE_DECLINED       603
#define SIP_CODE_PARTY_HANGS_UP 701

#define SIP_HUNG_UP_RING_TIME   8*1000              // milli seconds
#define SIP_ERROR_TIMEOUT       60*1000             // reset error state after timeout
#define SIP_ERROR_MIN           1000
#define ERROR_STATE             (SIP_ERROR_MIN + __LINE__)   // location of runtime error. Try Command SipState

typedef struct {
    char user[10] = SIP_FRITZBOX_USER;
    char password[20] = SIP_FRITZBOX_PASSWORD;
    char ipStr[16] = SIP_FRITZBOX_IP;
    IPAddress ip;
    uint16_t port = SIP_FRITZBOX_PORT;
} SIP_CONFIG;

typedef struct {
    char dial_nr[10] = DIAL_NR;
    char dial_user[10] = DIAL_USER;
    char peer[16] = PEERIP;
    char realm[16] = PEERIP;
    int cseq;
    int callID = 4711;      // random number?
    int contentLength;
    char myIP[16] = LOCAL_IP;
    int  myPort = LOCAL_PORT;
    char nonce[20];
    char tag[20];
    char digest[40];
    char request[8];
    char uri[5+10+16+1];
} SIP_PARAM;

typedef struct {
    bool button_state;
    int sip_state;
    int sip_code;
    int ringcount;
    unsigned int pkg_received;
    unsigned int loops;
    bool timeout_started;
    uint32_t timer_timeout;
    uint32_t timer_ringtime;
#define                 MAXRINGHISTORY  8
    int ringhistoryidx;  
    uint32_t ringhistory[MAXRINGHISTORY];
} SIP_DATA;

// global memory

WiFiUDP             sipUdp;
SIP_CONFIG          sipConfig;
SIP_PARAM           sipParam;
SIP_DATA            sipData;
char                sip_inBuf[1024];        // UDP receive buffer
char                sip_outBuf[1024];       // UDP send buffer
MD5Builder          md5Builder;

// sip functions

void SipInitConfig(int index, char* target) {
    char * confVar = SettingsText(SET_MEM1+index-1); // use 1..5
    if (*confVar)
        strcpy(target, confVar);
}
void SipInitConfigs() {
    SipInitConfig(1, sipParam.dial_nr);
    SipInitConfig(2, sipParam.dial_user);
    SipInitConfig(3, sipConfig.user);
    SipInitConfig(4, sipConfig.password);
    SipInitConfig(5, sipConfig.ipStr);
}

void SipUdpListen() {
    if (WL_CONNECTED != Wifi.status) {
        sipData.sip_state = ERROR_STATE;
        return;
    }
    sipData.sip_state = ERROR_STATE;    // before connect
    sipUdp.stop();
    sipConfig.ip.fromString(sipConfig.ipStr);
    if (!sipUdp.begin(sipParam.myPort)) {
        sipData.sip_state = ERROR_STATE;
        return;
    }
    strcpy(sipParam.myIP, WiFi.localIP().toString().c_str());
    sipData.sip_state = SIP_STATE_IDLE;
}

// Build sip request. Mostly do not care about irrelevant header fields.
void SipBuildRequest(char* out, size_t size) {
    char auth[300];
    if (sipParam.digest[0] != 0) {
        snprintf(auth, sizeof(auth), 
            PSTR("Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", Algorithm=MD5\r\n"),
            sipConfig.user, sipParam.realm, sipParam.nonce, sipParam.uri, sipParam.digest );
    } else {
        auth[0] = 0;
    }

    char tag[40];
    if (sipParam.tag[0])
        snprintf(tag, sizeof(tag), ";tag=%s", sipParam.tag);
    else
        tag[0] = 0;

    snprintf(out, size, PSTR(
    "%s sip:%s@%s SIP/2.0\r\n"
    "Call-ID: %d@%s\r\n"
    "Via: SIP/2.0/UDP %s:%d\r\n"
    "CSeq: %d %s\r\n"
    "%s" // auth
    "From: \"%s\" <sip:%s@%s>\r\n"
    "To: <sip:%s@%s>%s\r\n"
    "Contact: <sip:%s@%s:%d;transport=udp>\r\n"
    "Content-Length: %d\r\n\r\n")
    , sipParam.request, sipParam.dial_nr, sipParam.realm
    , sipParam.callID, sipParam.myIP
    , sipParam.myIP, sipParam.myPort
    , sipParam.cseq, sipParam.request
    , auth
    , sipParam.dial_user, sipConfig.user, sipParam.realm
    , sipParam.dial_nr, sipParam.peer, tag
    , sipParam.dial_user, sipParam.myIP, sipParam.myPort
    , sipParam.contentLength
    );
}

void SipSendUdp(char* buf) {
    AddLogData(LOG_LEVEL_DEBUG, buf);
    int rc = sipUdp.beginPacket(sipConfig.ip, sipConfig.port);
    if (0 == rc) {
        sipData.sip_state = ERROR_STATE;
        return;
    }
    size_t len = strlen(buf);
    sipUdp.write((const uint8_t*)buf, len);
    rc = sipUdp.endPacket();
    if (0 == rc)
        sipData.sip_state = ERROR_STATE;
}

void SipSendRequest(const char* request) {
    strncpy(sipParam.request, request, sizeof(sipParam.request));
    if (sipParam.nonce[0]) {
        SipGetDigest(sipConfig.user, sipParam.realm, sipConfig.password, sipParam.request, sipParam.uri, sipParam.nonce, sipParam.digest);
    }
    SipBuildRequest(sip_outBuf, sizeof(sip_outBuf));
    SipSendUdp(sip_outBuf);
}

void SipSendInvite(int state = SIP_STATE_INVITE) {
    sipData.sip_state = state;
    SipSendRequest("INVITE");
}
void SipSendBye() {
    sipData.sip_state = SIP_STATE_BYE;
    SipSendRequest("BYE");
}
void SipSendAck() {
    sipData.sip_state = SIP_STATE_ACK;
    SipSendRequest("ACK");
}
void SipSendOk() {
    sipData.sip_state = SIP_STATE_OK;
    SipSendRequest("OK");
}
void SipSendCancel() {
    sipData.sip_state = SIP_STATE_CANCEL;
    SipSendRequest("CANCEL");
}

// get value out of key="string" or key=1234\r\n
void SipGetString(char* buf, const char* key, char* out) {
    char* value = strstr(buf, key);
    if (value != 0) {
        value += strlen(key);
        if (*value == '"')
            value++;
        while (*value > '"')
            *out++ = *value++;
    }
    *out = 0;
}

void SipCalcMD5(char* inUtf8str, char* out) {
    md5Builder.begin();
    md5Builder.add(inUtf8str);
    md5Builder.calculate();
    md5Builder.getChars(out);
}
void SipGetDigest(const char* user, const char* realm, const char* password, const char* request, const char* uri, const char* nonce, char* out)
{
    char ha1[40], ha2[40], tmp[3*40];
    snprintf(tmp, sizeof(tmp), "%s:%s:%s", user, realm, password);
    SipCalcMD5(tmp, ha1);
    snprintf(tmp, sizeof(tmp), "%s:%s", request, uri);
    SipCalcMD5(tmp, ha2);
    snprintf(tmp, sizeof(tmp), "%s:%s:%s", ha1, nonce, ha2);
    SipCalcMD5(tmp, out);
}

// Parse UAS answer setting sipData.sip_code. Handle 401.
void SipParsePackage() {
    char* p = strchr(sip_inBuf, ' ');
    if (p == 0) {
        sipData.sip_state = ERROR_STATE;
        return;
    }
    if (strcmp(sip_inBuf,"BYE")==0) {
        sipData.sip_code = SIP_CODE_PARTY_HANGS_UP;
        return;
    }
    sipData.sip_code = atoi(++p);

    // Do some security check?
    // got same tag or digest otherwise ignore package.

    sipParam.digest[0] = 0;
    if (SIP_STATE_INVITE == sipData.sip_state && 
        SIP_CODE_UNAUTHORIZED == sipData.sip_code) {
        
        SipSendAck();

        // To: <sip:**613@fritz.box>;tag=123BCBCD74560CC1
        SipGetString(sip_inBuf, "tag=", sipParam.tag);
        if (sipParam.tag[0] == 0) {
            sipData.sip_state = ERROR_STATE;
            return;
        }
        // WWW-Authenticate: Digest realm="fritz.box", nonce="1231456115FCBF1D"
        SipGetString(sip_inBuf, "nonce=", sipParam.nonce);
        if (sipParam.nonce[0] == 0) {
            sipData.sip_state = ERROR_STATE;
            return;
        }
        // uri="sip:**613@fritz.box",
        snprintf(sipParam.uri, sizeof(sipParam.uri), "sip:%s@%s", sipParam.dial_nr, sipParam.realm);
        SipSendInvite(SIP_STATE_INVITE_401);
    }
 }

void SipReceiveUdp() {
    int packetSize = sipUdp.parsePacket();
    if (packetSize) {
        int len = sipUdp.read(sip_inBuf, sizeof(sip_inBuf)-1);
        if (len > 0) {
            ++ sipData.pkg_received;
            sip_inBuf[len] = 0;
            AddLogData(LOG_LEVEL_DEBUG, sip_inBuf);
            SipParsePackage();
        }
    }
}

// Syntax of command: SipSet config=value
void Sip_cmd_set() {
    ResponseClear();
    if (XdrvMailbox.data_len > 0) {
        char* value = strchr(XdrvMailbox.data, '=');
        if (value)
            ++value;
         //------------------- param struct ---------------------------- 
        if (strncmp(XdrvMailbox.data, PSTR("dial_nr %s"), 7)==0) {
            if (value)
                strncpy(sipParam.dial_nr, value, sizeof(sipParam.dial_nr));
            ResponseAppend_P(PSTR("dial_nr %s"), sipParam.dial_nr);
        } else if (strncmp(XdrvMailbox.data, PSTR("dial_user %s"), 8)==0) {
            if (value)
                strncpy(sipParam.dial_user, value, sizeof(sipParam.dial_user));
            ResponseAppend_P(PSTR("dial_user %s"), sipParam.dial_user);
        } else if (strncmp(XdrvMailbox.data, PSTR("peer %s"), 4)==0) {
            if (value)
                strncpy(sipParam.peer, value, sizeof(sipParam.peer));
            ResponseAppend_P(PSTR("peer %s"), sipParam.peer);
        } else if (strncmp(XdrvMailbox.data, PSTR("realm %s"), 5)==0) {
            if (value)
                strncpy(sipParam.realm, value, sizeof(sipParam.realm));
            ResponseAppend_P(PSTR("realm %s"), sipParam.realm);
        } else if (strncmp(XdrvMailbox.data, PSTR("myip %s"), 4)==0) {
            if (value)
                strncpy(sipParam.myIP, value, sizeof(sipParam.myIP));
            ResponseAppend_P(PSTR("myip %s"), sipParam.myIP);
        //------------------- config struct ----------------------------    
        } else if (strncmp(XdrvMailbox.data, PSTR("user %s"), 4)==0) {
            if (value)
                strncpy(sipConfig.user, value, sizeof(sipConfig.user));
            ResponseAppend_P(PSTR("user %s"), sipConfig.user);
        } else if (strncmp(XdrvMailbox.data, PSTR("pwd %s"), 3)==0) {
            if (value)
                strncpy(sipConfig.password, value, sizeof(sipConfig.password));
            ResponseAppend_P(PSTR("pwd %s"), sipConfig.password);
        } else if (strncmp(XdrvMailbox.data, PSTR("ipstr %s"), 2)==0) {
            if (value)
                strncpy(sipConfig.ipStr, value, sizeof(sipConfig.ipStr));
            ResponseAppend_P(PSTR("ipstr %s"), sipConfig.ipStr);
        } else if (strncmp(XdrvMailbox.data, PSTR("port %d"), 4)==0) {
            if (value)
                sipConfig.port = atoi(value);
            ResponseAppend_P(PSTR("port %d"), sipConfig.port);
        //------------------- unknown command ---------------------------- 
        } else {
            ResponseAppend_P(PSTR("unknown %s"), XdrvMailbox.data);
        }
    }
}

// simulate doorbell ring.
void Sip_cmd_test() {
    ResponseClear();
    // ring
    sipData.sip_state = SIP_STATE_DO_RING;
}

void SaveRingHistoryTime() {
    ++sipData.ringcount;
    sipData.ringhistory[sipData.ringhistoryidx] = LocalTime();
    ++ sipData.ringhistoryidx;     // advance for next entry
    if (sipData.ringhistoryidx >= MAXRINGHISTORY)
        sipData.ringhistoryidx = 0;
}
const char kDayNames[] PROGMEM = "SoMoDiMiDoFrSa";
void WSShowRingHistory() {
    int current = sipData.ringhistoryidx - 1;
    for(int idx=0; idx < MAXRINGHISTORY; ++idx) {
        if (current < 0)
            current = MAXRINGHISTORY - 1;
        if (0 != sipData.ringhistory[current]) {
            TIME_T tm;
            BreakTime(sipData.ringhistory[current], tm);
            WSContentSend_P(PSTR("{s}Ring at {m}%c%c %d.%d. %02d:%02d{e}"), 
                    kDayNames[(tm.day_of_week-1)*2], 
                    kDayNames[(tm.day_of_week-1)*2+1],
                    tm.day_of_month, tm.month,
                    tm.hour, tm.minute
                    );
        }
        -- current;
    }
}

void Sip_cmd_state() {
    if (XdrvMailbox.data_len > 0) {
        int opt = strtol(XdrvMailbox.data,nullptr,10);
        sipData.sip_state = opt;
        ResponseCmndDone();
    }
    Sip_callhistory(1);
}

void Sip_callhistory(bool json)
{
    if (json) {
        ResponseAppend_P(PSTR(",\"SipState\":{"));
        ResponseAppend_P(PSTR("\"Rings\": %d"), sipData.ringcount);
        ResponseAppend_P(PSTR(",\"State\": %d"), sipData.sip_state);
        ResponseAppend_P(PSTR(",\"Button\": %d"), sipData.button_state);
        ResponseAppend_P(PSTR(",\"PkgReceived\": %u"), sipData.pkg_received);
        ResponseAppend_P(PSTR(",\"Loops\": %u"), sipData.loops);
        ResponseJsonEnd();
    } 
#ifdef USE_WEBSERVER
    else {
        WSContentSend_P(PSTR("{s}Sip State{m}%d{e}"), sipData.sip_state);
        if (UpTime() < SHOW_EXTRA_INFO_SEC) { // show extra infos after restart
            WSContentSend_P(PSTR("{s}UDP Pkg received{m}%d{e}"), sipData.pkg_received);
            WSContentSend_P(PSTR("{s}Doorbell button {m}%d{e}"), sipData.button_state);
        }
        WSShowRingHistory();
    }
#endif
}

void SipDoorbellButtonHandler()
{
    sipData.button_state = XdrvMailbox.payload;
    if (sipData.sip_state < SIP_STATE_DO_RING && 
        0 == sipData.button_state) // pulled down
    {
        sipData.sip_state = SIP_STATE_DO_RING;
    } 
}

/*********************************************************************************************\
 * Driver Interface
\*********************************************************************************************/

const char sip_cmnd_names[] PROGMEM =
    "Sip|"
    "state|"
    "set|"
    "test"
    ;

void (*const sip_cmnds[])(void) PROGMEM = {
    &Sip_cmd_state, &Sip_cmd_set, &Sip_cmd_test
};    

bool Xdrv92(uint8_t function) {
    bool result = false;

    switch (function) {
        case FUNC_BUTTON_PRESSED:
            SipDoorbellButtonHandler();
            break;
        case FUNC_COMMAND:
		    result = DecodeCommand(sip_cmnd_names, sip_cmnds);
		    break;
        case FUNC_EVERY_250_MSECOND:
            ++sipData.loops;

            if (WL_CONNECTED != Wifi.status) {
                return false; // wait until wiffi is ready
            }
            if (sipData.timeout_started && TimeReached(sipData.timer_timeout)) {
                sipData.sip_state = SIP_STATE_INIT;     // Restart after timeout from error state.
                sipData.timeout_started = false;
            }
            if (SIP_CODE_INVALID <= sipData.sip_state) {
                if (!sipData.timeout_started) {
                    SetNextTimeInterval(sipData.timer_timeout, SIP_ERROR_TIMEOUT);      
                    sipData.timeout_started = true;
                }
                return false;
            }
            // action upon current state
            switch (sipData.sip_state) {
                case SIP_STATE_INIT:
                    SipInitConfigs();
                    SipUdpListen();
                    break;
                case SIP_STATE_DO_RING:
                    ++sipParam.cseq;
                    ++sipParam.callID;
                    sipParam.nonce[0] = 0;
                    sipParam.digest[0] = 0;
                    sipParam.tag[0] = 0;
                    SaveRingHistoryTime(); // once per ring
                    SetNextTimeInterval(sipData.timer_timeout, SIP_ERROR_TIMEOUT);      
                    sipData.timeout_started = true;
                    SipSendInvite();
                    break;
                case SIP_STATE_RINGING:
                    if (TimeReached(sipData.timer_ringtime))
                       SipSendCancel();
                    break;
                case SIP_STATE_IDLE:
                case SIP_STATE_OK:
                case SIP_STATE_CANCEL:
                case SIP_STATE_INVITE_401: 
                    break;      // do nothing while awaiting answer from UAS
            }
            
            SipReceiveUdp();    // Poll UDP receive buffer
            // UAS responses
            switch (sipData.sip_code) {
                case SIP_CODE_REQUEST_CANCELLED:
                case SIP_CODE_DECLINED:
                case SIP_CODE_OK:
                    SipSendAck();   // => state = ok
                    break;
                case SIP_CODE_RINGING:
                case SIP_CODE_TRYING:
                    SetNextTimeInterval(sipData.timer_ringtime, SIP_HUNG_UP_RING_TIME);
                    sipData.sip_state = SIP_STATE_RINGING;
                    break;
                case SIP_CODE_PROGRESS:
                    break;
                case SIP_CODE_PARTY_HANGS_UP:
                    SipSendOk();
                    break;
            }
            sipData.sip_code = SIP_CODE_LISTENING;
            break;
        case FUNC_JSON_APPEND:
            Sip_callhistory(1);
            break;
#ifdef USE_WEBSERVER
        case FUNC_WEB_SENSOR:
            Sip_callhistory(0);
            break;
#endif // USE_WEBSERVER
    }
    return result;
}
#endif // USE_SIP
