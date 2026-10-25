#!/usr/bin/env bash
# AES-256 LoRaWAN test vectors (docs/aes256_lorawan.md): the exact bytes an AES-256 device and our ChirpStack fork must
# both produce, for LoRaWAN 1.0.3 / 1.0.4 and 1.1, ABP and OTAA. Made with the openssl command line only, so they
# depend on neither ChirpStack's lrwn nor our C code. The controls check openssl's AES-256 and AES-256-CMAC against
# NIST's answers and its KDF against two plain CMACs (what a device computes); then it prints the vectors.
#   bash scripts/aes256_vectors.sh            (OpenSSL 3.x; OSSL= points at another openssl)
set -euo pipefail
OSSL=${OSSL:-openssl}

aes() {    # aes <key> <blocks>: AES-256 encryption of each 16-byte block
    echo "$2" | xxd -r -p | "$OSSL" enc -aes-256-ecb -K "$1" -nopad | xxd -p | tr -d '\n'; }
aes_d() {  # aes_d <key> <blocks>: AES-256 decryption of each block (how the join-accept is encrypted)
    echo "$2" | xxd -r -p | "$OSSL" enc -d -aes-256-ecb -K "$1" -nopad | xxd -p | tr -d '\n'; }
cmac() {   # cmac <key> <data>: AES-256-CMAC
    echo "$2" | xxd -r -p | "$OSSL" mac -cipher AES-256-CBC -macopt hexkey:"$1" CMAC | tr 'A-F' 'a-f'; }
# Session keys: the 16-byte block LoRaWAN derives each key from (key type | its fields | zero padding) goes into NIST
# SP 800-108's KDF in counter mode with AES-256-CMAC, for 32 bytes: CMAC(root, 00000001 | block | 00 | 00000100) |
# CMAC(root, 00000002 | block | 00 | 00000100), the block as the KDF's label, no context
kdf() {    # kdf <root key> <16-byte derivation block>
    "$OSSL" kdf -binary -keylen 32 -kdfopt mac:CMAC -kdfopt cipher:AES-256-CBC -kdfopt hexkey:"$1" -kdfopt hexsalt:"$2" \
        KBKDF | xxd -p | tr -d '\n'; }
xor() {  # xor <data> <keystream at least as long>
    local o="" i; for ((i = 0; i < ${#1}; i += 2)); do o+=$(printf %02x $(( 0x${1:i:2} ^ 0x${2:i:2} ))); done; echo "$o"; }
le() { local o="" i; for ((i = 0; i < $2; i++)); do o+=$(printf %02x $(( ($1 >> 8 * i) & 255 ))); done; echo "$o"; }
hexlen() { printf %02x $(( ${#1} / 2 )); }

# FRMPayload (and FPort 0's MAC commands): A_i = 01 | 0^4 | Dir | DevAddr | FCnt | 00 | i
frm() {  # frm <key> <dir 00|01> <devaddr, frame order> <fcnt> <data>
    local s="" i; for ((i = 1; i <= (${#5} / 2 + 15) / 16; i++)); do
        s+=$(aes "$1" "0100000000$2$3$(le "$4" 4)00$(printf %02x $i)"); done
    xor "$5" "$s"; }
# FOpts (1.1 only; plain in 1.0.x): A = 01 | 0^3 | 01, or 02 on a downlink with FPort > 0 (AFCntDown) | Dir | DevAddr | FCnt | 00 | 01
fopts() {  # fopts <NwkSEncKey> <01|02> <dir> <devaddr> <fcnt> <data>
    xor "$6" "$(aes "$1" "01000000$2$3$4$(le "$5" 4)0001")"; }
# MIC blocks: B0 = 49 | 0^4 | Dir | DevAddr | FCnt | 00 | len; B1 (1.1 uplink) = 49 | ConfFCnt | TxDr | TxCh | 00 | ...
# ConfFCnt (2 bytes, 1.1) counts only when the frame's ACK bit is set; a 1.1 downlink's B0 carries it in bytes 1-2
mic10() {  # mic10 <NwkSKey> <dir> <devaddr> <fcnt> <msg>: 1.0.x, both directions
    local m; m=$(cmac "$1" "4900000000$2$3$(le "$4" 4)00$(hexlen "$5")$5"); echo "${m:0:8}"; }
mic_up11() {  # mic_up11 <FNwkSIntKey> <SNwkSIntKey> <devaddr> <fcnt> <conf> <txdr> <txch> <msg>
    local n; n=$(hexlen "$8")
    local s f; s=$(cmac "$2" "49$(le "$5" 2)$6${7}00$3$(le "$4" 4)00$n$8"); f=$(cmac "$1" "490000000000$3$(le "$4" 4)00$n$8")
    echo "${s:0:4}${f:0:4}"; }
mic_down11() {  # mic_down11 <SNwkSIntKey> <devaddr> <fcnt> <conf> <msg>
    local m; m=$(cmac "$1" "49$(le "$4" 2)000001$2$(le "$3" 4)00$(hexlen "$5")$5"); echo "${m:0:8}"; }
# Joins. Join-request MIC: CMAC(AppKey (1.0.x) or NwkKey (1.1), MHDR | JoinEUI | DevEUI | DevNonce). Join-accept MIC:
# CMAC(AppKey, MHDR | payload) in 1.0.x, CMAC(JSIntKey, FF | JoinEUI | DevNonce | MHDR | payload) in 1.1 (FF: a join-request
# answered); payload = JoinNonce | NetID | DevAddr | DLSettings | RxDelay [| CFList]. Then payload | MIC is AES-decrypted
# with AppKey (1.0.x) or NwkKey (1.1), so the device only needs AES encryption to read it.
mic4() { local m; m=$(cmac "$1" "$2"); echo "${m:0:8}"; }

fail=0
check() { if [ "$2" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: got $2, expected $3"; fail=1; fi; }

echo "== Controls: openssl against NIST's answers, and its KDF against two CMACs"
check "AES-256 block (FIPS 197 C.3)" \
    "$(aes 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 00112233445566778899aabbccddeeff)" \
    8ea2b7ca516745bfeafc49904b496089
check "AES-256 decryption (FIPS 197 C.3)" \
    "$(aes_d 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 8ea2b7ca516745bfeafc49904b496089)" \
    00112233445566778899aabbccddeeff
K=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
check "AES-256-CMAC, empty message (SP 800-38B ex. 9)" "$(cmac $K "")" 028962f61b7bf89efc6b551f4667d983
check "AES-256-CMAC, 64 bytes (SP 800-38B ex. 12)" "$(cmac $K 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710)" \
    e1992190549f6ed5696a2c056c315410
# what a device computes instead: two CMACs
B=01010000130000010000000000000000
check "KBKDF = two CMACs" "$(kdf $K $B)" "$(cmac $K 00000001${B}0000000100)$(cmac $K 00000002${B}0000000100)"
[ $fail = 0 ] || { echo "a control failed: this openssl's AES-256, CMAC or KDF is wrong, so no vectors" >&2; exit 1; }

show() { echo "$1"; shift; for kv in "$@"; do echo "  $kv"; done; echo; }
P=$(printf '{"seq":1,"temp_c":21.5,"rh":48}' | xxd -p | tr -d '\n')   # the 31-byte reading
D=67452301                                                             # DevAddr 01234567, in frame order

echo
echo "== LoRaWAN 1.1, ABP: DevAddr 01234567"
A=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # AppSKey
F=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f   # FNwkSIntKey
S=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f   # SNwkSIntKey
E=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f   # NwkSEncKey

C=$(frm $A 00 $D 1 "$P"); M=40${D}00010001$C; MIC=$(mic_up11 $F $S $D 1 0 02 01 "$M")
show "V1 uplink: unconfirmed, FCnt 1, FPort 1, the reading, TxDr 2, TxCh 1" \
    "FRMPayload plain  $P" "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

FO=$(fopts $E 01 00 $D 2 067307); C=$(frm $A 00 $D 2 6869); M=40${D}230200${FO}01$C; MIC=$(mic_up11 $F $S $D 2 7 05 02 "$M")
show "V2 uplink: ACK of downlink 7 (ConfFCnt 7), FCnt 2, FOpts DevStatusAns 067307 (NwkSEncKey), FPort 1 \"hi\", TxDr 5, TxCh 2" \
    "FOpts             $FO" "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

FO=$(fopts $E 02 01 $D 5 020701); C=$(frm $A 01 $D 5 01020304); M=60${D}030500${FO}01$C; MIC=$(mic_down11 $S $D 5 0 "$M")
show "V3 downlink: AFCntDown 5, FOpts LinkCheckAns 020701 (NwkSEncKey, AFCntDown block), FPort 1 01020304" \
    "FOpts             $FO" "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

C=$(frm $E 01 $D 9 0351ff0001); M=60${D}20090000$C; MIC=$(mic_down11 $S $D 9 3 "$M")
show "V4 downlink: ACK of uplink 3 (ConfFCnt 3), NFCntDown 9, FPort 0: LinkADRReq 0351ff0001 in FRMPayload (NwkSEncKey)" \
    "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

echo "== LoRaWAN 1.0.3 / 1.0.4, ABP (the same bytes in both): DevAddr 01234567"
A=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # AppSKey
N=808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f   # NwkSKey

C=$(frm $A 00 $D 1 "$P"); M=40${D}03010006730701$C; MIC=$(mic10 $N 00 $D 1 "$M")
show "V5 uplink: unconfirmed, FCnt 1, FOpts DevStatusAns 067307 (plain in 1.0.x), FPort 1, the reading" \
    "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

C=$(frm $N 01 $D 4 0351ff0001); M=60${D}20040000$C; MIC=$(mic10 $N 01 $D 4 "$M")
show "V6 downlink: ACK, FCntDown 4, FPort 0: LinkADRReq 0351ff0001 in FRMPayload (NwkSKey)" \
    "FRMPayload        $C" "MIC               $MIC" "frame             $M$MIC"

echo "== OTAA: JoinEUI 1122334455667788, DevEUI 0102030405060708, DevNonce 1, JoinNonce 1, NetID 000013, DevAddr 01234567"
J=8877665544332211; V=0807060504030201; DN=0100; JN=010000; NID=130000   # in frame order (little-endian)

AK=a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf  # AppKey (1.0.x: the only root key)
M=00$J$V$DN
show "V7 1.0.x join-request" "frame             $M$(mic4 $AK "$M")"
PL=$JN$NID${D}0201; MIC=$(mic4 $AK "20$PL")
show "V8 1.0.x join-accept: DLSettings 02 (RX2 DR2), RxDelay 1, no CFList" \
    "plain             20 $PL $MIC" "frame             20$(aes_d $AK "$PL$MIC")" \
    "NwkSKey           $(kdf $AK 01$JN$NID${DN}00000000000000)" "AppSKey           $(kdf $AK 02$JN$NID${DN}00000000000000)"

NK=c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf  # NwkKey (1.1)
AK=e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff  # AppKey (1.1)
M=00$J$V$DN
show "V9 1.1 join-request" "frame             $M$(mic4 $NK "$M")"
JS=$(kdf $NK 06${V}00000000000000); PL=$JN$NID${D}8201; MIC=$(mic4 $JS "ff$J${DN}20$PL")
show "V10 1.1 join-accept: DLSettings 82 (OptNeg, RX2 DR2), RxDelay 1, no CFList" \
    "JSIntKey          $JS" "plain             20 $PL $MIC" "frame             20$(aes_d $NK "$PL$MIC")" \
    "FNwkSIntKey       $(kdf $NK 01$JN$J${DN}0000)" "AppSKey           $(kdf $AK 02$JN$J${DN}0000)" \
    "SNwkSIntKey       $(kdf $NK 03$JN$J${DN}0000)" "NwkSEncKey        $(kdf $NK 04$JN$J${DN}0000)"
