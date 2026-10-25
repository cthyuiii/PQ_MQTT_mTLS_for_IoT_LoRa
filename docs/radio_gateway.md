# The radio gateway: a Pi 5 with the SX1303 HAT

How machine 1 (ChirpStack and the gateway, README "What runs") gets a real radio. **Not run on the hardware yet.**
Checked so far: Semtech's packet forwarder builds on arm64 Debian 12 and 13 (gcc 12 and 14), and reads the AS923
configuration below.

```text
LoRa device ─radio, AS923─► SX1303 HAT ─SPI─► packet forwarder ─UDP, 127.0.0.1:1700─► Gateway Bridge ═PQ═► MQTT broker
(Pico W + SX1262 HAT)       (on the Pi 5)     (lora_pkt_fwd, Semtech)                   (Go 1.27, Docker)   (machine 2)
```

- **The HAT** is a concentrator: it listens on 8 channels at once and hands every frame it hears to the packet
  forwarder. It doesn't decrypt anything; the frame stays as the device sent it.
- **The packet forwarder** (Semtech's `lora_pkt_fwd`) talks to the HAT over SPI and sends each frame as Semtech UDP to
  the Gateway Bridge. That UDP is plain, so it stays on this Pi: the Bridge listens on 127.0.0.1 only.
- **The Gateway Bridge** is the one `chirpstack_pq_setup.sh` starts with `GATEWAY_IMAGE=`. Nothing changes there for
  the radio: `virtual_gateway.py` sent the same UDP.

**Band:** Singapore uses AS923 (920-925 MHz). The 915M HAT covers it. ChirpStack's `as923` region listens for uplinks
on 923.2 and 923.4 MHz; the configuration below covers 922.0-923.4 MHz.

**Before powering on:** screw the antenna onto the HAT. Transmitting without one can damage the radio.

## 1. Pi OS: SPI and I2C on

The HAL talks to the SX1303 over SPI (`/dev/spidev0.0`), and reads the HAT's temperature sensor over I2C
(`/dev/i2c-1`; it stops if it can't).

```bash
sudo raspi-config nonint do_spi 0 && sudo raspi-config nonint do_i2c 0 && sudo reboot
# after the reboot
ls /dev/spidev0.0 /dev/i2c-1
sudo apt-get install -y git build-essential i2c-tools
sudo i2cdetect -y 1          # the HAT's temperature sensor shows at 39
```

## 2. Build Semtech's packet forwarder

```bash
git clone -b V2.1.0 https://github.com/Lora-net/sx1302_hal.git ~/sx1302_hal
cd ~/sx1302_hal && make
```

## 3. The reset script, for the Pi 5

`lora_pkt_fwd` and `chip_id` run `./reset_lgw.sh start` from their own folder before they touch the chip. Semtech's
script writes `/sys/class/gpio/<n>`, and the Pi 5 no longer numbers those like the header pins, so it fails there.
This one uses `pinctrl` (part of Raspberry Pi OS), which takes the header's BCM numbers. The pins are the CoreCell
reference values: check them against your HAT's pinout first (wrong pins show as step 7's first error).

```bash
cat > ~/sx1302_hal/reset_lgw.sh <<'EOF'
#!/bin/sh
SX1302_RESET_PIN=23     # SX1302 reset
SX1302_POWER_EN_PIN=18  # SX1302 power enable
SX1261_RESET_PIN=22     # SX1261 reset
case "$1" in
start)
    pinctrl set $SX1302_POWER_EN_PIN op dh; sleep 0.1
    pinctrl set $SX1302_RESET_PIN op dh; sleep 0.1; pinctrl set $SX1302_RESET_PIN op dl; sleep 0.1
    pinctrl set $SX1261_RESET_PIN op dl; sleep 0.1; pinctrl set $SX1261_RESET_PIN op dh; sleep 0.1 ;;
stop) ;;
*) echo "usage: $0 start|stop" >&2; exit 1 ;;
esac
EOF
chmod +x ~/sx1302_hal/reset_lgw.sh
cp ~/sx1302_hal/reset_lgw.sh ~/sx1302_hal/packet_forwarder/ && cp ~/sx1302_hal/reset_lgw.sh ~/sx1302_hal/util_chip_id/
```

## 4. The gateway's ID

```bash
cd ~/sx1302_hal/util_chip_id && ./chip_id      # → INFO: concentrator EUI: 0x0016c001ff......
```

This is the gateway's ID: in the packet forwarder's configuration (next step) and in ChirpStack.

## 5. The configuration: AS923 over SPI

Semtech's only AS923 file is for its USB board. The same file over SPI, with:

- listen-before-talk off: it's Japan's AS923 rule, and it needs an SX1261 the HAT may not have;
- this gateway's ID;
- the Bridge's port, 1700.

```bash
cd ~/sx1302_hal/packet_forwarder
EUI=<the 16 hex digits from step 4, without 0x>
sed -e 's|"com_type": "USB"|"com_type": "SPI"|' -e 's|"com_path": "/dev/ttyACM0"|"com_path": "/dev/spidev0.0"|' \
    -e '/"lbt": {/{n;s|"enable": true|"enable": false|}' \
    -e "s|\"gateway_ID\": \"[0-9A-Fa-f]*\"|\"gateway_ID\": \"$EUI\"|" \
    -e 's|"serv_port_up": [0-9]*|"serv_port_up": 1700|' -e 's|"serv_port_down": [0-9]*|"serv_port_down": 1700|' \
    global_conf.json.sx1250.AS923.USB > global_conf.json
```

## 6. ChirpStack: the setup on this Pi, and the gateway registered

On this Pi 5, as on the Mac (README "Run it"): both images built here (arm64), then
`CHIRPSTACK_IMAGE=… GATEWAY_IMAGE=… chirpstack_pq_setup.sh`, then `docker compose up`.

In ChirpStack's UI (`http://<this pi>:8080`): Gateways → Add gateway, with the gateway ID from step 4. Its region comes
from the MQTT topic (`as923/…`).

## 7. Run it

```bash
cd ~/sx1302_hal/packet_forwarder && ./lora_pkt_fwd -c global_conf.json
```

What to look for:

- **`concentrator started, packet can now be received`:** the HAT is up.
- **`PUSH_ACK received`** (in the statistics, every 30 s): the Bridge answered.
- **In ChirpStack,** the gateway shows as online.
- **Each frame from a device** shows as a `JSON up` line here, then as `as923/gateway/<ID>/event/up` on the broker.

When it fails:

| Message | Likely cause |
|---|---|
| chip version `0x00`, or `failed to set SX1250 … in STANDBY_RC mode` | wrong reset pins (step 3), or SPI off |
| `failed to configure the temperature sensor` | I2C off (step 1) |
| no `PUSH_ACK` | the Bridge isn't running, or not on 127.0.0.1:1700 |
| `pinctrl: not found` | not Raspberry Pi OS: use `gpioset` (libgpiod) in step 3 instead |

Keep it running after a reboot with a systemd service (`WorkingDirectory=` the packet_forwarder folder, so it finds
`reset_lgw.sh`).

## Next: the device's radio

The Pico W firmware sends its LoRaWAN frames over Wi-Fi to `virtual_gateway.py` today. For the radio it needs a driver
for the SX1262 HAT that transmits the same frames on 923.2 / 923.4 MHz (AS923, LoRaWAN's public sync word: `0x3444` on
the SX1262), and listens for the reply in RX1 / RX2. The frames themselves don't change.
