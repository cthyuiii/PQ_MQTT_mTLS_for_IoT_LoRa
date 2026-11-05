// The STM32WL as a LoRaWAN test device for the testbed (docs/testbed.md step 9): no sensors, an uplink every NODE_S
// seconds on FPort 1 ({"n":<count>}), then Home Assistant's answer ("ack <FCnt>") in RX1 or RX2. ABP (no join: DevAddr
// and session keys built in), LoRaWAN 1.0.4, AES-128: ST's LoRaWAN stack as STM32duino's STM32LoRaWAN library has it,
// AS923-1. Built and flashed by stm32/run_node.sh; node_secrets.h (DevAddr, NwkSKey, AppSKey as hex) is made from the
// provisioning file for that build only.
//
// Serial, 115200 (PA2 / PA3: on the LM402 kit, its ST-Link's serial port):
//   #device ...                                   once at start
//   #up <n> FCnt <f> DR<d>: <ms> ms               an uplink and its receive windows done, <ms> from the send
//   #down <n> FCntDown <f> port <p> RSSI <r> SNR <s>: <text>   the answer to uplink <n>; "#down <n> none" if none
//   #count up <u> down <d>                        after each uplink
#include <STM32LoRaWAN.h>
#include "node_secrets.h"

#ifndef NODE_S
#define NODE_S 60
#endif
#ifndef NODE_DR
#define NODE_DR 0  // SF12, as the Picos; AS923's 400 ms dwell limit (ST's default) holds it at DR2 (SF10)
#endif

STM32LoRaWAN modem;
static uint32_t ups, downs, next_ms;

void setup() {
    Serial.begin(115200);
    Serial.printf("#device ABP (no join: DevAddr and session keys built in), LoRaWAN %d.%d.%d, AES-128: STM32WL, "
                  "ST's stack (STM32LoRaWAN), AS923-1\n", (int)(LORAMAC_VERSION >> 24), (int)(LORAMAC_VERSION >> 16 & 0xff),
                  (int)(LORAMAC_VERSION >> 8 & 0xff));  // the version the library was built with
    if (!modem.begin(AS923)) {
        Serial.println("#error modem.begin(AS923)");
        while (true) {}
    }
    modem.setADR(false);  // the data rate stays where it is set
    if (!modem.dataRate(NODE_DR))
        Serial.printf("#dr DR%d refused (AS923's dwell limit): DR%d\n", NODE_DR, modem.getDataRate());
    modem.setPort(1);     // Home Assistant answers FPort 1 only
    if (!modem.joinABP(NODE_DEVADDR, NODE_NWKSKEY, NODE_APPSKEY)) {
        Serial.println("#error joinABP: DevAddr or a key not 8 / 32 hex digits");
        while (true) {}
    }
    // ponytail: FCnt starts at 0 at every reset (the library can't set it); ChirpStack's counters back to 0 on the
    // device's Activation tab after one. A counter kept in flash (MIB_NVM_CTXS) if resets get frequent.
    Serial.printf("#node every %d s: {\"n\":<count>} on FPort 1, DevAddr %s\n", NODE_S, NODE_DEVADDR);
    next_ms = millis();
}

void loop() {
    if ((int32_t)(millis() - next_ms) < 0)
        return;
    next_ms += NODE_S * 1000UL;
    char msg[16];  // 11 bytes at most at DR2 under the dwell limit: n up to 99999
    int len = snprintf(msg, sizeof msg, "{\"n\":%lu}", (unsigned long)++ups);
    modem.beginPacket();
    modem.write((const uint8_t *)msg, len);
    uint32_t t0 = millis();
    int sent = modem.endPacket();  // blocks: the uplink, then RX1 and (with nothing in RX1) RX2
    uint32_t ms = millis() - t0;
    if (sent < 0)
        Serial.printf("#up %lu failed after %lu ms\n", (unsigned long)ups, (unsigned long)ms);
    else
        Serial.printf("#up %lu FCnt %ld DR%d: %lu ms\n", (unsigned long)ups, (long)modem.getFCU(),
                      modem.getDataRate(), (unsigned long)ms);
    if (modem.available()) {
        char rx[65];
        int n = modem.read((uint8_t *)rx, sizeof rx - 1);
        for (int i = 0; i < n; i++)
            if (rx[i] < 32 || rx[i] > 126) rx[i] = '.';
        rx[n] = 0;
        downs++;
        Serial.printf("#down %lu FCntDown %ld port %u RSSI %d SNR %d: %s\n", (unsigned long)ups, (long)modem.getFCD(),
                      modem.getDownlinkPort(), modem.getDownlinkRssi(), modem.getDownlinkSnr(), rx);
    } else {
        Serial.printf("#down %lu none\n", (unsigned long)ups);
    }
    Serial.printf("#count up %lu down %lu\n", (unsigned long)ups, (unsigned long)downs);
}
