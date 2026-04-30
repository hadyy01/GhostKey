/*
 * ============================================================
 * SecIoT — PUF Enrollment Firmware
 *
 * Run this sketch ONCE on every new NodeMCU/ESP32 before
 * deploying the main device_client firmware.
 *
 * What it does:
 *   1. Reads the SRAM startup state (power-on SRAM PUF).
 *   2. Applies von Neumann debiasing.
 *   3. Hashes to a 256-bit device fingerprint via SHA-256.
 *   4. Sends "ENROLL:<hex_fingerprint>" to the RPi Key Server,
 *      which stores it in its device registry.
 *   5. RPi responds "ENROLLED:OK" and the device is ready.
 *
 * After this, flash device_client.ino for normal operation.
 *
 * Author: Khan Hady Khamis
 * ============================================================
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WebSocketsClient.h>
#include <SHA256.h>

const char*    WIFI_SSID      = "YOUR_SSID";
const char*    WIFI_PASSWORD  = "YOUR_PASSWORD";
const char*    KEY_SERVER_IP  = "192.168.1.137";
const uint16_t KEY_SERVER_PORT = 9000;

IPAddress staticIP(192, 168, 1, 100);
IPAddress gateway(192, 168, 1, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress dns(8, 8, 8, 8);

WebSocketsClient enrollSocket;
bool enrollmentDone = false;

/* ── SRAM PUF (identical implementation to device_client) ── */

static uint8_t vonNeumannDebias(uint32_t raw, uint8_t &out, uint8_t &bitPos) {
    for (int i = 0; i < 30; i += 2) {
        uint8_t b0 = (raw >> i)     & 1;
        uint8_t b1 = (raw >> (i+1)) & 1;
        if (b0 != b1) {
            out |= (b0 << bitPos);
            bitPos++;
            if (bitPos == 8) return 1;
        }
    }
    return 0;
}

void sramPufFingerprint(uint8_t fingerprint[32]) {
    volatile uint32_t* sramBase = (volatile uint32_t*)0x3FFE8000;
    uint8_t rawBits[16] = {0};
    uint8_t byteIdx = 0;
    uint8_t bitPos  = 0;

    for (int w = 0; w < 64 && byteIdx < 16; w++) {
        uint32_t word = sramBase[w];
        uint8_t out   = 0;
        uint8_t bpos  = 0;
        if (vonNeumannDebias(word, out, bpos)) {
            rawBits[byteIdx++] = out;
        }
    }

    SHA256 sha;
    sha.update(rawBits, 16);
    sha.finalize(fingerprint, 32);
}

/* ── WebSocket enrollment handler ────────────────────────── */

void enrollSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED:
            Serial.println(F("[ENROLL] Connected to key server."));
            {
                uint8_t fp[32];
                sramPufFingerprint(fp);

                String msg = "ENROLL:";
                for (int i = 0; i < 32; i++) {
                    char hex[3];
                    sprintf(hex, "%02x", fp[i]);
                    msg += hex;
                }
                enrollSocket.sendTXT(msg.c_str());
                Serial.println(F("[ENROLL] Sent enrollment fingerprint."));
                Serial.print(F("[ENROLL] Fingerprint: "));
                Serial.println(msg.substring(7));
            }
            break;

        case WStype_TEXT:
            if (strncmp((char*)payload, "ENROLLED:OK", 11) == 0) {
                Serial.println(F("\n[ENROLL] ✓ Enrollment SUCCESS."));
                Serial.println(F("[ENROLL] You may now flash device_client.ino."));
                enrollmentDone = true;
            } else {
                Serial.printf("[ENROLL] Server: %s\n", payload);
            }
            break;

        case WStype_DISCONNECTED:
            Serial.println(F("[ENROLL] Disconnected."));
            break;
        default:
            break;
    }
}

void setup() {
    Serial.begin(115200);
    delay(100);
    Serial.println(F("\n=== SecIoT PUF Enrollment Sketch ==="));

    WiFi.disconnect();
    WiFi.config(staticIP, dns, gateway, subnet);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(300); Serial.print('.');
    }
    Serial.println(F("\nWiFi connected."));

    enrollSocket.begin(KEY_SERVER_IP, KEY_SERVER_PORT, "/");
    enrollSocket.onEvent(enrollSocketEvent);
    enrollSocket.setReconnectInterval(5000);
}

void loop() {
    if (!enrollmentDone) {
        enrollSocket.loop();
    } else {
        // Blink rapidly to indicate success
        digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
        delay(200);
    }
}
