#!/usr/bin/env python3
"""Scan for Tuya BLE (Parkside/Lidl "dcb" category) smart batteries and read status.

Reuses the protocol implementation from
custom_components/tuya_ble/tuya_ble/ (pairing, session-key derivation, packet
framing/parsing) so we don't reimplement the Tuya BLE wire protocol. That
subpackage has no Home Assistant dependency itself, but its *parent* package
(custom_components/tuya_ble/__init__.py) does, so it is loaded directly from
its file path rather than via a normal package import.

Credentials (uuid, local_key, device_id/"id", category, product_id) are read
from a Tuya IoT export CSV such as batteries/tuya-local-key (1).csv.

Devices are identified without relying on the CSV containing a MAC address
(it doesn't have a "mac" column): every Tuya BLE advertisement broadcasts an
AES-encrypted UUID that decrypts using nothing but the device's product_id
(MD5(product_id) as both AES key and IV -- see decrypt_advertised_uuid()).
Each scanned advertisement is decrypted with every known product_id from the
CSV and matched against the CSV's uuid column; a match tells us which CSV row
a given (possibly unknown, possibly rotating) MAC address belongs to. This is
the same mechanism this repo's own tuya_ble.py uses internally
(_decode_advertisement_data) and the one documented in ARDUINO.md for a
future ESP32 port -- see that file for the full protocol writeup.

Usage:
    ./battery_status.py                      # scan + read all devices in the CSV
    ./battery_status.py --csv path/to.csv
    ./battery_status.py --timeout 20
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import enum
import glob
import hashlib
import importlib.util
import logging
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TUYA_BLE_PKG_DIR = REPO_ROOT / "custom_components" / "tuya_ble" / "tuya_ble"

DEFAULT_CSV_GLOB = str(Path(__file__).resolve().parent / "tuya-local-key*.csv")


def _load_tuya_ble_subpackage() -> types.ModuleType:
    """Load custom_components/tuya_ble/tuya_ble as a standalone package.

    A plain `import custom_components.tuya_ble.tuya_ble` would first execute
    custom_components/tuya_ble/__init__.py, which imports Home Assistant.
    We only need the inner subpackage, which is HA-free apart from a single
    `from ..const import DPType` used solely as a dataclass type annotation,
    so we stub that parent package with a minimal fake `const` module.
    """
    parent_pkg_name = "_tuya_ble_standalone"
    parent_pkg = types.ModuleType(parent_pkg_name)
    parent_pkg.__path__ = []
    sys.modules[parent_pkg_name] = parent_pkg

    fake_const = types.ModuleType(f"{parent_pkg_name}.const")

    class DPType(str, enum.Enum):
        BOOLEAN = "Boolean"
        ENUM = "Enum"
        INTEGER = "Integer"
        JSON = "Json"
        RAW = "Raw"
        STRING = "String"

    fake_const.DPType = DPType
    sys.modules[f"{parent_pkg_name}.const"] = fake_const

    pkg_name = f"{parent_pkg_name}.tuya_ble"
    spec = importlib.util.spec_from_file_location(
        pkg_name,
        TUYA_BLE_PKG_DIR / "__init__.py",
        submodule_search_locations=[str(TUYA_BLE_PKG_DIR)],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg_name] = module
    spec.loader.exec_module(module)
    return module


tuya_ble = _load_tuya_ble_subpackage()

TuyaBLEDevice = tuya_ble.TuyaBLEDevice
TuyaBLEDataPointType = tuya_ble.TuyaBLEDataPointType
AbstaractTuyaBLEDeviceManager = tuya_ble.AbstaractTuyaBLEDeviceManager
TuyaBLEDeviceCredentials = tuya_ble.TuyaBLEDeviceCredentials
SERVICE_UUIDS = tuya_ble.SERVICE_UUIDS

from bleak import BleakScanner  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402

MANUFACTURER_DATA_ID = tuya_ble.const.MANUFACTURER_DATA_ID

_LOGGER = logging.getLogger("battery_status")

# dp_id -> (label, unit). Sourced from this repo's own confirmed "dcb" /
# PARKSIDE Smart battery (product_id ajrhf1aj / z5ztlw3k) mappings in
# devices.py, sensor.py, binary_sensor.py, switch.py, select.py and
# number.py/text.py -- not from AI speculation. dp172 (battery_temp_current)
# is mapped by the integration but these battery units never actually send
# it, so it always reads n/a here.
BATTERY_STATUS_OPTIONS = ["Ready", "Charging", "Discharging", "Full", "Sleep", "Error"]
BATTERY_WORK_MODE_OPTIONS = ["Performance", "Balanced", "Eco", "Expert"]

DCB_DATAPOINTS: dict[int, tuple[str, str]] = {
    16: ("battery_percentage", "%"),
    11: ("temperature", "C"),
    172: ("battery_temp_current", "C"),
    102: ("battery_status", ""),
    2: ("charge_current", "mA"),
    3: ("charge_voltage", "mV"),
    8: ("charge_times", ""),
    9: ("discharge_times", ""),
    10: ("peak_current_times", ""),
    12: ("upper_temp_switch", ""),
    14: ("use_time", "min"),
    15: ("runtime_total", "min"),
    19: ("product_type", ""),
    21: ("fault", ""),
    22: ("security_switch", ""),
    101: ("discharging_current", "mA"),
    103: ("charge_to_full_time", "min"),
    104: ("discharge_to_empty_time", "s"),
    105: ("battery_work_mode", ""),
    106: ("battery_pin", ""),
    107: ("over_voltage_times", ""),
    108: ("under_voltage_times", ""),
    109: ("overtemp_discharge_times", ""),
    110: ("overtemp_charge_times", ""),
    111: ("undertemp_discharge_times", ""),
    112: ("undertemp_charge_times", ""),
    113: ("short_circuit_times", ""),
    114: ("over_current_times", ""),
    116: ("low_discharge_voltage", "mV"),
    117: ("discharge_current_limit", "A"),
    118: ("power_indicator_time", "s"),
}

# Small "core" subset the wait-for-datapoints loop blocks on. Everything else
# in DCB_DATAPOINTS is displayed opportunistically but not waited for -- some
# DPs (e.g. 172) are mapped by the integration for this category but simply
# never sent by these particular battery units, so waiting on the full set
# would always burn the whole timeout.
CORE_DATAPOINTS = (16, 11, 102)


def load_credentials_from_csv(csv_path: Path) -> list[TuyaBLEDeviceCredentials]:
    credentials = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            creds = TuyaBLEDeviceCredentials(
                uuid=row["uuid"],
                local_key=row["local_key"],
                device_id=row["id"],
                category=row["category"],
                product_id=row["product_id"],
                device_name=row["name"],
                product_model=None,
                product_name=row.get("product_name"),
                functions=[],
                status_range=[],
            )
            credentials.append(creds)
    return credentials


class StaticDeviceManager(AbstaractTuyaBLEDeviceManager):
    """Serves credentials parsed from the CSV export, keyed by BLE MAC address.

    The MAC a given device is currently using is not known upfront (the CSV
    has no mac column) -- entries are registered dynamically once
    match_credentials_by_uuid() identifies which CSV row a scanned
    advertisement belongs to.
    """

    def __init__(self) -> None:
        self._address_to_credentials: dict[str, TuyaBLEDeviceCredentials] = {}

    def register(self, address: str, credentials: TuyaBLEDeviceCredentials) -> None:
        self._address_to_credentials[address.upper()] = credentials

    async def get_device_credentials(
        self,
        address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        return self._address_to_credentials.get(address.upper())


def decrypt_advertised_uuid(raw_product_id: bytes, encrypted_uuid: bytes) -> str | None:
    """Decrypt the UUID a Tuya BLE device broadcasts in its advertisement.

    Mirrors TuyaBLEDevice._decode_advertisement_data (tuya_ble.py): the AES-128
    key is MD5(raw_product_id), used as both the key AND the IV (a
    Tuya-specific quirk for this one advertisement field -- the main session
    protocol uses a proper random IV).

    IMPORTANT: raw_product_id here is the *raw 8 bytes broadcast in the
    advertisement's service_data* -- NOT the ASCII product_id string from the
    CSV (e.g. "ajrhf1aj"). Those are different values; an earlier version of
    this function mistakenly tried CSV product_id strings as the key and
    always failed. Verified empirically against a real captured
    advertisement: MD5(advertised 8 bytes) correctly decrypts to the exact
    uuid string from that device's CSV row. The advertisement is
    self-describing -- no CSV lookup is needed to derive the key, only to
    check the *result* against known uuids.
    """
    key = hashlib.md5(raw_product_id, usedforsecurity=False).digest()
    cipher = AES.new(key, AES.MODE_CBC, key)
    try:
        return cipher.decrypt(encrypted_uuid).decode("utf-8")
    except UnicodeDecodeError:
        return None


def extract_advertised_identity(advertisement_data) -> tuple[bytes, bytes] | None:
    """Pull (raw_product_id, encrypted_uuid) out of a Tuya BLE advertisement.

    Mirrors TuyaBLEDevice._decode_advertisement_data (tuya_ble.py:432-464).
    Returns None if this advertisement doesn't carry both fields (e.g. it's
    not a Tuya device, or is missing manufacturer/service data this scan).
    """
    raw_product_id: bytes | None = None
    if advertisement_data.service_data:
        for service_uuid in SERVICE_UUIDS:
            service_data = advertisement_data.service_data.get(service_uuid)
            if service_data and len(service_data) > 1 and service_data[0] == 0:
                raw_product_id = service_data[1:]
                break
    if raw_product_id is None:
        return None

    manufacturer_data = (advertisement_data.manufacturer_data or {}).get(MANUFACTURER_DATA_ID)
    if not manufacturer_data or len(manufacturer_data) <= 6:
        return None
    encrypted_uuid = manufacturer_data[6:]

    return raw_product_id, encrypted_uuid


def match_credentials_by_uuid(
    advertisement_data,
    credentials_by_uuid: dict[str, TuyaBLEDeviceCredentials],
) -> TuyaBLEDeviceCredentials | None:
    """Identify which known device (if any) sent this advertisement.

    No MAC address is used or needed: the advertisement carries its own key
    material (raw_product_id bytes), which decrypts directly to the device's
    uuid -- look that up in the CSV-derived table. This is the general-purpose
    approach documented in ARDUINO.md, adopted here instead of parsing a MAC
    out of the CSV "name" column (which happened to work only because this
    particular export embeds it there).
    """
    identity = extract_advertised_identity(advertisement_data)
    if identity is None:
        return None
    raw_product_id, encrypted_uuid = identity

    decrypted_uuid = decrypt_advertised_uuid(raw_product_id, encrypted_uuid)
    if decrypted_uuid is None:
        return None
    return credentials_by_uuid.get(decrypted_uuid)


class LiveScanner:
    """A BleakScanner kept running for the program's whole lifetime.

    BlueZ can drop its D-Bus object for a device shortly after the scanner
    that discovered it stops, which makes a stop-then-connect sequence
    unreliable ("device not found" / "device disappeared" at connect time,
    even moments after a successful discovery). Keeping one scanner running
    continuously -- across discovery *and* every connect attempt -- avoids
    that gap, mirroring how Home Assistant's own bluetooth manager works.

    Every advertisement is also checked against the known-device credential
    table by decrypting its broadcast UUID (see match_credentials_by_uuid) --
    no MAC address needs to be known ahead of time. Resolved devices are
    tracked by uuid (the CSV's stable identity), with the MAC address learned
    on the fly and updated on every subsequent advertisement in case it
    rotates.
    """

    def __init__(self, credentials_by_uuid: dict[str, TuyaBLEDeviceCredentials]) -> None:
        self._credentials_by_uuid = credentials_by_uuid
        self._resolved_by_uuid: dict[str, tuple[TuyaBLEDeviceCredentials, str, object, object]] = {}
        self._scanner = BleakScanner(self._callback)

    def _callback(self, device, advertisement_data) -> None:
        mac = device.address.upper()
        creds = match_credentials_by_uuid(advertisement_data, self._credentials_by_uuid)
        if creds is not None:
            self._resolved_by_uuid[creds.uuid] = (creds, mac, device, advertisement_data)

    async def start(self) -> None:
        await self._scanner.start()

    async def stop(self) -> None:
        await self._scanner.stop()

    async def wait_for_uuid(
        self, uuid: str, timeout: float
    ) -> tuple[TuyaBLEDeviceCredentials, str, object, object] | None:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            entry = self._resolved_by_uuid.get(uuid)
            if entry:
                return entry
            await asyncio.sleep(0.25)
        return self._resolved_by_uuid.get(uuid)


def format_value(dp_id: int, dp) -> str:
    if dp is None:
        return "n/a"
    label, unit = DCB_DATAPOINTS.get(dp_id, (str(dp_id), ""))
    value = dp.value
    if dp_id == 102 and isinstance(value, int) and 0 <= value < len(BATTERY_STATUS_OPTIONS):
        value = BATTERY_STATUS_OPTIONS[value]
    elif dp_id == 105 and isinstance(value, int) and 0 <= value < len(BATTERY_WORK_MODE_OPTIONS):
        value = BATTERY_WORK_MODE_OPTIONS[value]
    return f"{value}{unit}"


async def read_device_status(
    uuid: str,
    manager: StaticDeviceManager,
    scanner: LiveScanner,
    resolve_timeout: float,
    dp_wait_timeout: float,
) -> None:
    resolved = await scanner.wait_for_uuid(uuid, resolve_timeout)
    if resolved is None:
        print(f"\n=== uuid={uuid} ===\n  ERROR: device not found in a fresh scan (out of range?)")
        return
    credentials, mac, ble_device, advertisement_data = resolved
    print(f"\n=== {credentials.device_name} ({mac}) ===")

    # Advertisement decryption identified which CSV row this MAC belongs to;
    # register it so TuyaBLEDevice.initialize() -> get_device_credentials(mac)
    # resolves to the right credentials for the actual pairing handshake.
    manager.register(mac, credentials)

    device = TuyaBLEDevice(manager, ble_device, advertisement_data)
    await device.initialize()
    try:
        await device._ensure_connected()
        await device.update()
        # update() only waits for the device to acknowledge the status
        # request; the actual datapoint values trickle in afterwards as
        # separate, asynchronous notifications. Poll until every DP we
        # care about has arrived, or give up after dp_wait_timeout.
        loop = asyncio.get_event_loop()
        deadline = loop.time() + dp_wait_timeout
        while loop.time() < deadline:
            if all(device.datapoints[dp_id] is not None for dp_id in CORE_DATAPOINTS):
                break
            await asyncio.sleep(0.5)
    except Exception as ex:  # noqa: BLE001
        print(f"  ERROR: failed to connect/read: {ex}")
        return
    finally:
        await device.stop()

    all_dps = device.datapoints.__dict__()

    print("  -- core --")
    for dp_id in CORE_DATAPOINTS:
        label = DCB_DATAPOINTS[dp_id][0]
        print(f"  {label:24s}: {format_value(dp_id, all_dps.get(dp_id))}")

    known_diagnostic_ids = [
        dp_id for dp_id in DCB_DATAPOINTS if dp_id not in CORE_DATAPOINTS and dp_id in all_dps
    ]
    if known_diagnostic_ids:
        print("  -- other known datapoints --")
        for dp_id in known_diagnostic_ids:
            label = DCB_DATAPOINTS[dp_id][0]
            print(f"  {label:24s}: {format_value(dp_id, all_dps.get(dp_id))}")

    unknown_ids = sorted(set(all_dps) - set(DCB_DATAPOINTS))
    if unknown_ids:
        print("  -- unrecognized datapoints (no label mapping in this repo) --")
        for dp_id in unknown_ids:
            dp = all_dps[dp_id]
            print(f"  dp{dp_id:<4d}: {dp.value!r} ({dp.type.name})")


async def main_async(args: argparse.Namespace) -> int:
    csv_matches = [Path(args.csv)] if args.csv else [Path(p) for p in glob.glob(DEFAULT_CSV_GLOB)]
    csv_matches = [p for p in csv_matches if p.exists()]
    if not csv_matches:
        print(f"No credentials CSV found (looked for {DEFAULT_CSV_GLOB!r}).", file=sys.stderr)
        return 1
    csv_path = csv_matches[0]
    print(f"Loading credentials from {csv_path}")
    credentials_list = load_credentials_from_csv(csv_path)

    # Keyed by uuid (not by mac -- the CSV has no mac column). Each
    # advertisement decrypts directly to a uuid using its own broadcast key
    # material, so this is a plain lookup, not something to search/guess.
    credentials_by_uuid: dict[str, TuyaBLEDeviceCredentials] = {
        creds.uuid: creds for creds in credentials_list
    }

    manager = StaticDeviceManager()

    scanner = LiveScanner(credentials_by_uuid)
    await scanner.start()
    try:
        _LOGGER.info(
            "Scanning for BLE advertisements for up to %.0fs per device "
            "(these batteries only advertise intermittently, e.g. after being "
            "touched or docked); devices are identified by decrypting their "
            "advertised uuid, no MAC address needed ...",
            args.timeout,
        )

        resolved_uuids = []
        for creds in credentials_list:
            if await scanner.wait_for_uuid(creds.uuid, args.timeout):
                resolved_uuids.append(creds.uuid)
            else:
                print(f"Not seen during scan: {creds.device_name} (uuid={creds.uuid})")

        if not resolved_uuids:
            print(
                "\nNo known devices were found in range. Wake them (press the "
                "button / dock them) and try again, or increase --timeout."
            )
            return 1

        for uuid in resolved_uuids:
            await read_device_status(uuid, manager, scanner, args.resolve_timeout, args.dp_wait_timeout)
    finally:
        await scanner.stop()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", help="Path to Tuya IoT export CSV (default: auto-detect in batteries/)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Max seconds to wait per device for it to be seen advertising (default: 30)",
    )
    parser.add_argument(
        "--resolve-timeout",
        type=float,
        default=10.0,
        help="Per-device scan duration used to re-resolve a fresh BLEDevice right before connecting (default: 10)",
    )
    parser.add_argument(
        "--dp-wait-timeout",
        type=float,
        default=10.0,
        help="Seconds to wait after update() for all known datapoints to arrive (default: 10)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
