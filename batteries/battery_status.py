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

_LOGGER = logging.getLogger("battery_status")

# dp_id -> (label, unit, decoder)
BATTERY_STATUS_OPTIONS = ["Ready", "Charging", "Discharging", "Full", "Sleep", "Error"]

DCB_DATAPOINTS: dict[int, tuple[str, str]] = {
    16: ("battery_percentage", "%"),
    11: ("temperature", "C"),
    172: ("battery_temp_current", "C"),
    102: ("battery_status", ""),
}

# Unverified/AI-generated guesses for additional dcb-category datapoints, not
# confirmed against Tuya documentation, firmware source, or the Lidl/Parkside
# app. Two independent LLM guesses disagreed on several of these (noted with
# "or"), which is itself a sign none of this should be trusted without
# empirical verification (e.g. watch a DP while actually charging/discharging
# at a known current, or compare against the app's displayed values). Shown
# only as a hint alongside the raw value in the "other datapoints" section.
GUESSED_DP_LABELS: dict[int, str] = {
    2: "current, mA? (0 when idle)",
    3: "pack voltage, mV/10=V? (e.g. 2520 -> 25.2V or 20.2V)",
    8: "charge cycles or peak-current indicator?",
    9: "discharge cycles or event counter?",
    10: "overcurrent count or charger/dock-connected flag?",
    12: "overheat/fault alarm (bool)?",
    14: "charge cycles or use-time (min)?",
    15: "runtime total (min) or operating hours?",
    19: "product model (string, e.g. 'PAPS 208 A1')",
    21: "fault bitmap (0 = no fault)?",
    22: "security switch or cell-balancing-active (bool)?",
    101: "discharge current, mA or 0.1A units?",
    103: "charge time remaining (min) or lock/eco mode?",
    104: "remaining runtime or remaining capacity (mWh/mAh)?",
    105: "work/performance mode (enum)?",
    106: "anti-theft PIN (string)",
    113: "voltage/cell-imbalance event count or health flag?",
    114: "cell fault bitfield?",
    116: "max charge/discharge current limit, mA?",
    117: "nominal capacity spec or charge timeout?",
    118: "firmware/BMS logic version?",
}


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
    """Serves credentials parsed from the CSV export, keyed by BLE MAC address."""

    def __init__(self, address_to_credentials: dict[str, TuyaBLEDeviceCredentials]):
        self._address_to_credentials = address_to_credentials

    async def get_device_credentials(
        self,
        address: str,
        force_update: bool = False,
        save_data: bool = False,
    ) -> TuyaBLEDeviceCredentials | None:
        return self._address_to_credentials.get(address.upper())


def extract_mac_from_name(name: str) -> str | None:
    """Pull the trailing MAC address out of a Tuya-exported device name.

    The CSV names embed the BLE MAC, e.g. "Lidl Smart battery 8Ah DC:23:4D:EB:88:46".
    """
    parts = name.strip().split()
    if not parts:
        return None
    candidate = parts[-1]
    octets = candidate.split(":")
    if len(octets) == 6 and all(len(o) == 2 for o in octets):
        return candidate.upper()
    return None


class LiveScanner:
    """A BleakScanner kept running for the program's whole lifetime.

    BlueZ can drop its D-Bus object for a device shortly after the scanner
    that discovered it stops, which makes a stop-then-connect sequence
    unreliable ("device not found" / "device disappeared" at connect time,
    even moments after a successful discovery). Keeping one scanner running
    continuously -- across discovery *and* every connect attempt -- avoids
    that gap, mirroring how Home Assistant's own bluetooth manager works.
    """

    def __init__(self) -> None:
        self._found: dict[str, tuple[object, object]] = {}
        self._scanner = BleakScanner(self._callback)

    def _callback(self, device, advertisement_data) -> None:
        self._found[device.address.upper()] = (device, advertisement_data)

    async def start(self) -> None:
        await self._scanner.start()

    async def stop(self) -> None:
        await self._scanner.stop()

    def get(self, mac: str) -> tuple[object, object] | None:
        return self._found.get(mac.upper())

    async def wait_for(self, mac: str, timeout: float) -> tuple[object, object] | None:
        mac = mac.upper()
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            entry = self._found.get(mac)
            if entry:
                return entry
            await asyncio.sleep(0.25)
        return self._found.get(mac)


def format_value(dp_id: int, dp) -> str:
    if dp is None:
        return "n/a"
    label, unit = DCB_DATAPOINTS.get(dp_id, (str(dp_id), ""))
    value = dp.value
    if dp_id == 102 and isinstance(value, int) and 0 <= value < len(BATTERY_STATUS_OPTIONS):
        value = BATTERY_STATUS_OPTIONS[value]
    return f"{value}{unit}"


async def read_device_status(
    credentials: TuyaBLEDeviceCredentials,
    mac: str,
    manager: StaticDeviceManager,
    scanner: LiveScanner,
    resolve_timeout: float,
    dp_wait_timeout: float,
) -> None:
    print(f"\n=== {credentials.device_name} ({mac}) ===")

    resolved = await scanner.wait_for(mac, resolve_timeout)
    if resolved is None:
        print(f"  ERROR: device not found in a fresh scan (out of range?)")
        return
    ble_device, advertisement_data = resolved

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
            if all(device.datapoints[dp_id] is not None for dp_id in DCB_DATAPOINTS):
                break
            await asyncio.sleep(0.5)
    except Exception as ex:  # noqa: BLE001
        print(f"  ERROR: failed to connect/read: {ex}")
        return
    finally:
        await device.stop()

    for dp_id, (label, unit) in DCB_DATAPOINTS.items():
        dp = device.datapoints[dp_id]
        print(f"  {label:24s}: {format_value(dp_id, dp)}")

    all_dps = device.datapoints.__dict__()
    other_ids = sorted(set(all_dps) - set(DCB_DATAPOINTS))
    if other_ids:
        print("  -- other datapoints received (labels are unverified guesses) --")
        for dp_id in other_ids:
            dp = all_dps[dp_id]
            guess = GUESSED_DP_LABELS.get(dp_id)
            tag = f" [{guess}]" if guess else ""
            print(f"  dp{dp_id:<4d}{tag:35s}: {dp.value!r} ({dp.type.name})")


async def main_async(args: argparse.Namespace) -> int:
    csv_matches = [Path(args.csv)] if args.csv else [Path(p) for p in glob.glob(DEFAULT_CSV_GLOB)]
    csv_matches = [p for p in csv_matches if p.exists()]
    if not csv_matches:
        print(f"No credentials CSV found (looked for {DEFAULT_CSV_GLOB!r}).", file=sys.stderr)
        return 1
    csv_path = csv_matches[0]
    print(f"Loading credentials from {csv_path}")
    credentials_list = load_credentials_from_csv(csv_path)

    mac_to_credentials: dict[str, TuyaBLEDeviceCredentials] = {}
    for creds in credentials_list:
        mac = extract_mac_from_name(creds.device_name or "")
        if mac:
            mac_to_credentials[mac] = creds
        else:
            _LOGGER.warning("Could not extract MAC address from name %r", creds.device_name)

    manager = StaticDeviceManager(mac_to_credentials)

    scanner = LiveScanner()
    await scanner.start()
    try:
        _LOGGER.info(
            "Scanning for BLE advertisements for up to %.0fs per device "
            "(these batteries only advertise intermittently, e.g. after being "
            "touched or docked) ...",
            args.timeout,
        )

        in_range = []
        for mac, creds in mac_to_credentials.items():
            if await scanner.wait_for(mac, args.timeout):
                in_range.append((mac, creds))
            else:
                print(f"Not seen during scan: {creds.device_name} ({mac})")

        if not in_range:
            print(
                "\nNo known devices were found in range. Wake them (press the "
                "button / dock them) and try again, or increase --timeout."
            )
            return 1

        for mac, creds in in_range:
            await read_device_status(
                creds, mac, manager, scanner, args.resolve_timeout, args.dp_wait_timeout
            )
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
