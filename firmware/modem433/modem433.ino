// MODEM 433  -  the same modem as modem.ino for the four 433 MHz inter satellite link boards.
// Only the power on frequency differs (433.575 MHz); the bridge sets each board to its ISL frequency with CFG.
// Transmits on the uplink (868.1 MHz), listens on the downlink (869.525 MHz). Half-duplex.
// Host -> modem:  TX,<hex>                 transmit a frame
//                 CFG,<txMHz>,<rxMHz>      change frequencies (optional)
// Modem -> host:  PKT,<rssi>,<snr>,<hex>   received frame
//                 SENT,<bytes>,<status>,<airtime ms>
//                 CRCERR
// Tools: ESP32S3 Dev Module, USB CDC On Boot Enabled, PSRAM Disabled

#include <RadioLib.h>
#include <SPI.h>

#define SCK 12
#define MISO 13
#define MOSI 11
#define CS 10
#define DIO1 1
#define RST 5
#define BUSY 4

float txMHz = 433.575, rxMHz = 433.575;

SPIClass radioSPI(FSPI);
SX1262 radio = new Module(CS, DIO1, RST, BUSY, radioSPI);

volatile bool rxFlag = false;
void IRAM_ATTR onRadioIrq() { rxFlag = true; }
String line;

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

void listen() {
  radio.setFrequency(rxMHz);
  rxFlag = false;
  radio.startReceive();
}

void sendHex(const String &hex) {
  int n = hex.length() / 2;
  if (hex.length() % 2 || n < 1 || n > 255) { Serial.println("SENT,0,ERR,0"); return; }
  uint8_t pkt[255];
  for (int i = 0; i < n; i++) {
    int h = hexVal(hex[2 * i]), l = hexVal(hex[2 * i + 1]);
    if (h < 0 || l < 0) { Serial.println("SENT,0,ERR,0"); return; }
    pkt[i] = (h << 4) | l;
  }
  radio.standby();
  radio.setFrequency(txMHz);
  unsigned long t0 = millis();
  int st = radio.transmit(pkt, n);
  unsigned long air = millis() - t0;
  listen();
  Serial.printf("SENT,%d,%d,%lu\n", n, st, air);
}

void setup() {
#if ARDUINO_USB_CDC_ON_BOOT && ARDUINO_USB_MODE
  // A received frame is one line of about 540 characters. The USB transmit buffer is 256 by
  // default, so with no waiting allowed the rest of a line was dropped whenever the host was
  // briefly busy (ISL self test, 13 Nov: a 255 octet frame arrived as 241). A buffer that
  // holds several whole lines fixes that. The timeout stays 0: the modem must never wait for
  // the host, or it stops when no program has the port open (seen on 14 Nov with 250 ms).
  Serial.setTxBufferSize(4096);
#endif
  Serial.begin(115200);
#if ARDUINO_USB_CDC_ON_BOOT
  Serial.setTxTimeoutMs(0);
#endif
  delay(2000);
  radioSPI.begin(SCK, MISO, MOSI, CS);
  int st = radio.begin(rxMHz, 125.0, 9, 7, 0x12, 10, 8, 1.8, false);
  Serial.printf("MODEM begin() = %d\n", st);
  if (st != RADIOLIB_ERR_NONE) while (true) delay(1000);
  radio.setPacketReceivedAction(onRadioIrq);
  listen();
  Serial.printf("MODEM ready tx %.3f rx %.3f\n", txMHz, rxMHz);
}

void loop() {
  if (rxFlag) {
    rxFlag = false;
    uint8_t buf[256];
    int n = radio.getPacketLength();
    int st = (n > 0 && n <= 255) ? radio.readData(buf, n) : RADIOLIB_ERR_PACKET_TOO_LONG;
    if (st == RADIOLIB_ERR_NONE) {
      // one write for the whole line, so a frame is never delivered to the host in pieces
      static char out[32 + 2 * 255 + 4];
      int k = snprintf(out, 32, "PKT,%.1f,%.1f,", radio.getRSSI(), radio.getSNR());
      for (int i = 0; i < n; i++) k += sprintf(out + k, "%02X", buf[i]);
      out[k++] = '\n';
      Serial.write((const uint8_t *)out, k);
    } else if (st == RADIOLIB_ERR_CRC_MISMATCH) {
      Serial.println("CRCERR");
    }
    radio.startReceive();
  }
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (line.startsWith("TX,")) sendHex(line.substring(3));
      else if (line.startsWith("CFG,")) {
        int k = line.indexOf(',', 4);
        if (k > 0) {
          txMHz = line.substring(4, k).toFloat();
          rxMHz = line.substring(k + 1).toFloat();
          listen();
          Serial.printf("CFG,OK,%.3f,%.3f\n", txMHz, rxMHz);
        }
      }
      line = "";
    } else if (line.length() < 600) {
      line += c;
    }
  }
}
