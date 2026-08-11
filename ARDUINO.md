# Port Tuya BLE battery decoder to ESP32 (Arduino3/C++) — feasibility & implementation plan

## Context

`batteries/battery_status.py` talks to the Parkside/Lidl "dcb"-category smart
batteries over BLE from a PC, reusing this repo's Python protocol
implementation (`custom_components/tuya_ble/tuya_ble/`). This document assesses
whether the same decoder — pairing handshake, session-key crypto, packet
framing, KLV datapoint parsing — could run standalone on an ESP32 under the
Arduino framework (Arduino-ESP32 core, "Arduino3"), e.g. to build a dedicated
battery-status display/logger without a PC or Home Assistant in the loop.

**Verdict: feasible, including with zero cloud access and no MAC address in
the source data.** The wire protocol itself is compact, fully specified by
`tuya_ble.py`, and uses only crypto primitives (AES-128-CBC, MD5) that ESP32's
bundled mbedTLS already provides natively.

**Hard constraint: no cloud access at runtime.** All credentials must come
from the CSV export, transformed to JSON, and loaded into an NVS-backed
variable at boot — the firmware must never call Tuya's Cloud OpenAPI. This is
fully achievable: `custom_components/tuya_ble/cloud.py` only uses the Cloud
API to *originally populate* `local_key`/`sec_key`/`uuid` (lines 134-200) —
nothing in the BLE wire protocol itself (`tuya_ble.py`/`security.py`) makes
any cloud call. Once those fields exist (which they do, in the CSV), the
entire pairing/session/DP-read flow is self-contained local BLE + local
crypto.

**Hard constraint: MAC address may be absent from the CSV.** Confirmed still
feasible — MAC is not actually required by the protocol to find a device,
only used as a convenience key by this repo's Python code (because Home
Assistant's own OS-level bluetooth manager already hands it a `BLEDevice`
keyed by address). The real device-identification mechanism is already
implemented in `_decode_advertisement_data` (`tuya_ble.py:432-464`): every
Tuya BLE advertisement broadcasts an **encrypted UUID**, decryptable using
key material the *advertisement itself carries* (an opaque 8-byte value in
the service-data field — **not** the CSV's ASCII `product_id` string; those
are two different values, confirmed by testing both against a real captured
advertisement, see "Device discovery without MAC" below). This means the
firmware can scan for *any* nearby Tuya device, derive the decrypt key
straight from that device's own advertisement, and compare the decrypted
result against the CSV's `uuid` column — no CSV lookup or guessing is needed
to derive the key, only to check the decrypted uuid against known devices —
independent of MAC, and robust even if a device's MAC changes.

**Connection-management code must be redesigned, not ported.** The Python
`_ensure_connected`/`_release_client`/`_release_and_reconnect` logic
(`tuya_ble.py:667-983`) is full of BlueZ/Linux-specific reconnect-race
workarounds (referenced HA issue #170) that don't apply to ESP32's BLE stack
(NimBLE-Arduino). This section should be treated as background only —
firmware connection handling should be written fresh against NimBLE's actual
behavior, not translated line-by-line.

Everything else — packet framing, CRC16, AES/MD5, KLV parsing, the pairing
sequence — translates mechanically to C++ with no Python-specific idioms that
resist porting.

## Device discovery without MAC (advertisement UUID decrypt-and-match)

Verified against `tuya_ble.py:432-464`, **and against a real captured
advertisement** from one of this user's batteries (not just source-reading —
see "Empirical verification" below). This is the mechanism that makes
MAC-free operation possible, and needs to run as a scan phase *before* the
GATT-connect/pairing handshake described below. `batteries/battery_status.py`
adopts this same approach (`match_credentials_by_uuid`/
`decrypt_advertised_uuid`) rather than parsing a MAC out of the CSV's `name`
column, so the Python script and this firmware plan now agree on one
general-purpose device-identification strategy.

**Important correction**: the key material is **not** the CSV's ASCII
`product_id` string (e.g. `"ajrhf1aj"`). An earlier version of this plan and
of `battery_status.py` assumed that and it silently never matched anything.
The advertisement's service-data field carries its own opaque 8 raw bytes —
call them `raw_product_id` since that's the variable name `tuya_ble.py` uses,
but they are not equal to, and cannot be derived from, the CSV `product_id`
column. The advertisement is fully self-describing: use whatever bytes it
broadcasts as the key, and only consult the CSV afterward, to check the
*decrypted result* against known `uuid` values.

1. Scan BLE advertisements for the Tuya service UUID (`0000a201-...` or
   `0000fd50-...`, `const.py` `SERVICE_UUIDS`). Each matching advertisement's
   **service data** field carries `[0x00, raw_product_id(8B)...]` (byte 0 is a
   sub-type tag; `0` = product ID present, per `tuya_ble.py:446-448`) and its
   **manufacturer data** (company ID `0x07D0`, `MANUFACTURER_DATA_ID` in
   `const.py`) carries `[flags(1B), protocol_version(1B), reserved(4B),
   encrypted_uuid(rest)]`.
2. Compute `key = MD5(raw_product_id)` using the 8 bytes taken directly from
   this advertisement's own service-data — no CSV/NVS table involved yet.
3. Decrypt `encrypted_uuid` with **AES-128-CBC using `key` as both the key
   and the IV** (`AES.new(key, AES.MODE_CBC, key)`,
   `tuya_ble.py:462-463` — this key==IV construction is specific to this one
   advertisement-decrypt step; the main session protocol below uses a proper
   random IV). Result decodes as a UTF-8 `uuid` string.
4. Look up that decrypted `uuid` in the NVS JSON table (built from the CSV) —
   this is the only step that touches the CSV data. A match tells the
   firmware: this advertisement, from whatever MAC it currently has, is CSV
   row N — use that row's `local_key`/`device_id`/`sec_key` for the pairing
   handshake (`product_id` is not needed anywhere in the protocol itself, see
   "Recommended scope" below), and the advertisement's *current* MAC for the
   GATT connect.
5. No match (wrong UTF-8 decode, or decodes but isn't in the table) → not one
   of our devices, ignore and keep scanning.

This step only needs to run once per device per power-up/reconnect (to learn
its current MAC), not on every read cycle — cache the MAC after a successful
match for the rest of that session.

### Empirical verification

Confirmed against a live capture, not just source inspection. A real
advertisement from a Parkside 8Ah battery (CSV uuid `4abe2e2deb1b976f`,
product_id `ajrhf1aj`) was captured with `bleak`:
```
service_data:      00 a8 05 b3 41 d5 ab f9 95   (raw_product_id = a8 05 b3 41 d5 ab f9 95)
manufacturer_data:  80 03 00 00 01 00 d8 8d 56 d8 4d 41 58 26 5e 05 fb c9 71 08 7c 63
                    (encrypted_uuid = d8 8d 56 d8 4d 41 58 26 5e 05 fb c9 71 08 7c 63)
```
`MD5(a8 05 b3 41 d5 ab f9 95)` used as AES-128-CBC key+IV decrypts
`encrypted_uuid` to the ASCII string `4abe2e2deb1b976f` — an exact match to
that device's CSV `uuid` column. Trying `MD5("ajrhf1aj")` (the CSV
product_id string) instead produces garbage, not valid UTF-8 — confirming the
two byte sequences are unrelated and the advertisement's own bytes are the
only correct key source.

### Independent cross-verification: github.com/MrTup1/Parkside-Bluetooth

A third-party project (C++/NimBLE, targeting the identical PAPS 208 A1
hardware, unrelated to this repo) independently arrived at the same
advertisement-decrypt formula, which is strong external confirmation of the
mechanism above. Its `TuyaBLEAdvertisedDeviceInfo::fromBLEAdvertisedDevice()`
computes `digest = MD5(serviceData[1:])` and decrypts
`manufacturerData[8:24]` with AES-CBC using that digest as key+IV — at first
glance an "offset 8" vs. this plan's "offset 6" (`manufacturer_data[6:]`)
discrepancy, but they're the same byte range: NimBLE's raw manufacturer-data
buffer includes the 2-byte Tuya company ID (`0x07D0`) that `bleak` (and this
plan's byte offsets, which assume bleak's already-stripped buffers) strips
automatically. `8 - 2 = 6`. Confirmed by reconstructing MrTup1's full
(unstripped) buffer from this plan's real capture above and checking
`fullBuf[8:24] == manufacturer_data[6:]` byte-for-byte — true. **If the
firmware reads manufacturer data from NimBLE directly (not via a bleak-like
abstraction), use offset 8, not 6**, since NimBLE will include those 2
company-ID bytes at the front.

Two other relevant findings from the same project, worth carrying into
firmware bring-up:

- **`local_key` rotates whenever the battery is re-paired to the Lidl/Tuya
  phone app** (and possibly under other conditions not fully pinned down by
  that project either). A CSV export's `local_key` is a snapshot, not a
  permanent secret — if a previously-working firmware suddenly can't
  complete the `FUN_SENDER_PAIR` handshake with no protocol-level error,
  suspect a stale `local_key` before suspecting a code bug. Re-export
  `id`/`local_key` together from the cloud API (not just one), and avoid
  opening the phone app again before testing the new key.
- Their pairing/handshake sequence, security flag values (`0x04`
  local-key, `0x05` session-key), GATT service/characteristic UUIDs
  (`0x1910`/`0x2B10`/`0x2B11`), packet chunking at 20-byte MTU, and 6-type
  KLV datapoint model all independently match what's documented below from
  `tuya_ble.py` — no new corrections needed there, just confirmation.

## Protocol facts to carry into the C++ port (verified against source)

All verified directly against `custom_components/tuya_ble/tuya_ble/tuya_ble.py`
and `security.py` in this repo — treat this repo as the reference spec, not a
memory/summary of it, when writing the firmware.

**GATT layer** (`const.py`): two possible service/characteristic UUID pairs
depending on device generation —
`0000a201-.../00002b10-.../00002b11-...` (notify/write) or the FD50 variant
(`0000fd50-.../00000002-.../00000001-...`). `GATT_MTU = 20`. Confirm which pair
the Parkside batteries use empirically (their `manifest.json` bluetooth entry
lists both `a201` and `fd50` service_data_uuid — either is possible).

**Chunk framing** (`_build_packets`/`_notification_handler`,
`tuya_ble.py:1029-1085` and `:1600-1652`): first chunk is
`varint(packet_num=0) + varint(total_len) + (protocol_version<<4 as 1 byte) + ciphertext...`;
subsequent chunks are `varint(packet_num) + ciphertext...`. Varint = LEB128,
7 bits/byte, continuation bit 0x80, max 5 bytes
(`_pack_int`/`_unpack_int`, `tuya_ble.py:997-1027`) — direct C++ port, no
library needed.

**Encryption envelope**: `security_flag(1B) + IV(16B random) + AES-128-CBC(...)`.
Key selection by security_flag (`_get_key`, `tuya_ble.py:1282-1292`): 4 or 14 =
`login_key` (device-info exchange), 5 or 15 = `session_key` (everything after).
14/15 vs 4/5 depends on whether `sec_key` is present (protocol-v2 vs v1,
`security.py:60-68`).

**Decrypted frame layout** (post-CBC-decrypt): `seq_num(4B BE) + response_to(4B BE)
+ code(2B BE) + data_len(2B BE) + data[data_len] + CRC16(2B BE, only if present)
+ zero-pad to 16B boundary`. CRC16 (`_calc_crc16`, `tuya_ble.py:985-995`):
init `0xFFFF`, poly `0xA001` (reflected 0x8005) — this is **CRC-16/MODBUS**,
implement as a lookup table, no dependency needed.

**Key derivation** (`security.py`): `login_key = MD5(local_key[:6] + sec_key)`
(v2) or `MD5(local_key[:6])` (v1); `session_key = MD5(derivation_material +
device_random)` where `device_random` is bytes `[6:12]` of the
`FUN_SENDER_DEVICE_INFO` response payload — session key must be derived
immediately upon receiving that response, before sending the pairing request.

**Handshake sequence** (`_ensure_connected`, `tuya_ble.py:765-956`):
1. Connect, subscribe to notify characteristic.
2. Send `FUN_SENDER_DEVICE_INFO` (code `0x0000`, empty payload), encrypted with
   `login_key`. Response ≥46 bytes: `protocol_version = byte[2]` (determines v3
   vs v4 DP format for rest of session), `device_random = bytes[6:12]` → derive
   `session_key`.
3. Send `FUN_SENDER_PAIR` (code `0x0001`), payload = `uuid + local_key[:6] +
   device_id`, zero-padded to 44 bytes, encrypted with `session_key`
   (`_build_pairing_request`, `tuya_ble.py:353-362`). Response: 1 byte, `0` or
   `2` = paired OK.
4. Send `FUN_SENDER_DEVICE_STATUS` (code `0x0003`, empty) to request a status
   push (`update()`, `tuya_ble.py:374-376`) — this only triggers the push, it
   does not itself carry datapoint data.
5. Datapoints arrive asynchronously via `FUN_RECEIVE_DP*` family (codes
   `0x8001/0x8003/0x8004/0x8005` = v3, `0x8006/0x8007` = v4,
   `const.py:60-69`). Firmware must poll/wait for these after step 4, matching
   the approach already used in `battery_status.py`'s `dp_wait_timeout` loop —
   **not all DPs necessarily arrive in one push** (empirically confirmed: dp172
   is mapped by this repo's category table but never sent by these battery
   units at all).

**KLV datapoint format** (`_parse_datapoints`/`_encode_datapoints`,
`tuya_ble.py:1325-1389`, `:1667-1701`): `id(1B) + type(1B) + length(1B for v3 /
2B BE for v4) + value(length bytes)`, repeated. Type enum
(`TuyaBLEDataPointType`, `const.py:72-78`): `DT_RAW=0, DT_BOOL=1, DT_VALUE=2,
DT_STRING=3, DT_ENUM=4, DT_BITMAP=5`.

**Confirmed DP table for this battery** (already in this repo, sourced from
field-tested mappings, not speculation — reuse directly rather than
re-deriving): `custom_components/tuya_ble/devices.py` (category `"dcb"`,
product_ids `ajrhf1aj`/`z5ztlw3k`) plus the corresponding entries across
`sensor.py`, `switch.py`, `select.py`, `number.py`, `text.py`,
`binary_sensor.py` for the same category/product_ids. `batteries/battery_status.py`
(`DCB_DATAPOINTS` dict) already consolidates all of these into one place —
use that as the DP-ID reference table for the firmware rather than re-reading
six Python files.

**Known bug to carry forward, not repeat**: this repo's `sensor.py` maps dp3
(`charge_voltage`) with no coefficient (defaults to `1.0`), so it reports the
raw value directly as millivolts — but real captured raw values (2452-2532)
would mean ~2.5V, physically implausible for a pack labeled "20V" (5S Li-ion
is nominally ~18.5-21V). Cross-checked against MrTup1/Parkside-Bluetooth,
which documents a **×8 scale factor** for this DP; `raw * 8` lands at
19.6-20.3V across multiple real captures, matching the pack rating. The
firmware's DP-decode table should apply this ×8 factor for dp3, not the raw
`sensor.py` mapping. `battery_status.py` already applies this fix
(`DCB_VOLTAGE_SCALE`).

**Known open question, not yet resolved**: dp104's unit is ambiguous between
sources. This repo's `sensor.py` calls it `discharge_to_empty_time` in
**seconds**; MrTup1/Parkside-Bluetooth calls it `EstimatedLife` in **minutes**
("capped at 30720"). A real captured value (29184 at 94% battery charge) is
physically plausible as seconds (~8.1h remaining runtime) but implausible as
minutes (~20 days) — seconds is kept as the working assumption in
`battery_status.py`, but this is inference from one data point, not a
confirmed spec. Resolve empirically before relying on it: capture this DP
while a battery discharges under a known, steady load and see which unit
tracks real elapsed/remaining time correctly.

## mbedTLS mapping (all available in Arduino-ESP32 core, no extra libraries)

| Need | API |
|---|---|
| MD5 | `mbedtls_md5()` |
| AES-128-CBC encrypt/decrypt | `mbedtls_aes_setkey_enc/dec` + `mbedtls_aes_crypt_cbc` |
| Random 16-byte IV | `esp_fill_random()` |
| CRC16/MODBUS | hand-rolled table, no library |
| BLE central (GATT client) | NimBLE-Arduino (recommended over Bluedroid — smaller footprint, actively maintained, standard choice for ESP32 Arduino BLE-client projects) |

## Recommended scope for a first working port

1. **CSV → JSON → NVS, offline, no MAC needed**: a one-time (PC-side, not
   on-device) conversion of the Tuya export CSV into a compact JSON array,
   one object per device: `{"uuid", "local_key", "device_id", "sec_key"?,
   "name"?}` — omit `mac` entirely (not needed, as shown above), and omit
   `product_id`/`category` too: `battery_status.py`'s own credential loader
   found neither is read anywhere in the pairing/session/DP-decode path (both
   are only consulted by the real HA integration to pick *UI* sensor
   mappings) and dropped them, filling harmless placeholders instead — the
   firmware's JSON schema should match. `sec_key` is genuinely optional
   (omit it entirely if the CSV export doesn't have that column, same as this
   user's export) and only switches key derivation to protocol-v2 when
   present. Store this JSON blob as a single NVS string/blob value (ESP32 NVS
   supports blobs up to its partition size; a handful of battery entries will
   be well under any practical limit) and parse it at boot with ArduinoJson
   (already the de facto standard on this platform) into an in-memory array
   of credential structs.
2. **Scan phase before connect** (see "Device discovery without MAC" above):
   on boot/reconnect, run a NimBLE scan, and for each candidate advertisement
   derive the decrypt key from its *own* service-data bytes (not from the NVS
   table), decrypt its uuid, and check that single result against the NVS
   table — an O(1) lookup, not a search over known product_ids. Record the
   matched advertisement's current MAC against the matched credential-table
   row. Repeat per device if reading multiple batteries in one firmware.
3. **Single-connection, blocking/polling design per device**: simple state
   machine (`DISCONNECTED → CONNECTING → AWAITING_DEVICE_INFO →
   AWAITING_PAIR_ACK → PAIRED → AWAITING_STATUS`), driven from `loop()` with a
   NimBLE notify callback setting a "response ready" flag + seq_num — mirrors
   what `battery_status.py` already does logically, not the Python asyncio
   machinery. Multiple devices can be handled by cycling through this state
   machine per matched device rather than trying to run them concurrently.
4. **Reassembly buffer**: fixed `uint8_t` buffer (recommend 512 bytes — no
   observed packet from this device category has needed more, and the Python
   code has no upper bound here worth replicating), plus `expected_packet_num`
   and `expected_total_len` counters, matching `_notification_handler`'s state.
5. **DP decode**: only the confirmed DP table's fields need dedicated structs;
   unknown/unmapped DPs can be logged raw (id/type/value) exactly as
   `battery_status.py`'s "unrecognized datapoints" section already does.
6. **Reconnection**: keep it simple initially (reconnect from scratch on
   disconnect, re-run full handshake, including a fresh scan-and-match if the
   MAC might have changed) rather than porting BlueZ's watcher-leak
   workarounds — those don't apply to NimBLE's connection model.

## Verification

No firmware code has been written yet — this is a feasibility/design
reference. When implementation starts, end-to-end verification should be:
flash to real ESP32 hardware, confirm the scan-and-match step correctly
identifies a known device from its advertisement alone (serial log showing
decrypted UUID matching an NVS entry), confirm successful pairing (serial log
showing DEVICE_INFO → PAIR ack), confirm at least the core 3 DPs (16/11/102,
battery %/temperature/status) decode correctly against a real battery,
cross-checked against `battery_status.py`'s output from the same device for
consistency.
