"""Linux memory backend for Rabi-Ribi running under Wine/Proton.

Memory reads and writes use a restricted privileged helper to access
/proc/<pid>/mem. Remote allocation and item injection are not implemented.
"""

import asyncio
import struct
from pathlib import Path

from CommonClient import logger
from .privileged_game_memory import PrivilegedGameMemory
from ..data import data


# Keep these offsets synchronized with memory_io.py.
OFFSET_AREA_ID = 0x00DDBFA0
OFFSET_PLAYER_X = 0x010736C8
OFFSET_PLAYER_Y = 0x013EEF00
OFFSET_GIVE_ITEM_FUNC = 0x00016FA0
OFFSET_PLAYER_FROZEN = 0x01083190
OFFSET_EVENT_MAP = 0x00E0D200
OFFSET_ITEM_MAP = 0x00E3EB5C
OFFSET_INVENTORY_START = 0x016B200C
OFFSET_EVENT_START = 0x016B281C
OFFSET_EGG_START = 0x016BBDC0
OFFSET_MAX_HEALTH = 0x1725DD4
OFFSET_PLAYER_PAUSED = 0x01070E04
OFFSET_SCENERIO_INDICATOR = 0x00E6F8A0
OFFSET_IN_ITEM_GET_ANIMATION = 0x01724A94
OFFSET_IN_WARP_MENU = 0x01724C68
OFFSET_IN_COSTUME_MENU = 0x01725BD0
OFFSET_IN_SAVE_MENU = 0x01768F88
OFFSET_CURRENT_WARP_ID = 0x01725DB8
OFFSET_PLAYER_STATE = 0x016C13D8
OFFSET_PLAYER_STATE_HEALTH = 0x4E0

EXCLAMATION_POINT_ITEM_ID = 43
UNUSED_ITEM_ID_48 = 48
EVENT_FLAG_ID_START = 255
TILE_LENGTH = 64
EGG_ARRAY_LENGTH = 80 * 3 * 2

# Items whose basic inventory state can be tested without invoking game code.
# Multi-level upgrades and items with special handling are intentionally excluded.
# DIRECT_INVENTORY_ITEM_IDS = frozenset({
#     2, 5, 9, 10, 12, 13, 14, 22, 24, 25, 26, 27, 29, 31, 35,
#     *range(64, 95),
# })



class ProcessNotFound(Exception):
    """Raised when the Rabi-Ribi process cannot be found."""


class ProcessError(Exception):
    """Raised when accessing the target process fails."""


class LinuxProcessMemory:
    """Memory access to a Linux process through the privileged helper."""

    def __init__(self, pid: int, base_address: int):
        self.process_id = pid
        self.base_address = base_address
        self._helper = PrivilegedGameMemory(pid)

    @staticmethod
    def _find_pid(name: str) -> int:
        """Find a process whose command line and mappings match the game."""
        candidates = []
        wanted = name.casefold()

        try:
            entries = list(Path("/proc").iterdir())
        except OSError as exc:
            raise ProcessError(f"Cannot enumerate /proc: {exc}") from exc

        for entry in entries:
            if not entry.name.isdecimal():
                continue

            pid = int(entry.name)
            try:
                raw = (entry / "cmdline").read_bytes()
                args = [
                    part.decode(errors="replace")
                    for part in raw.split(b"\0")
                    if part
                ]

                if any(
                    Path(arg.replace("\\", "/")).name.casefold() == wanted
                    for arg in args
                ):
                    candidates.append(pid)
            except OSError:
                continue

        # The actual game process is often newer than the launcher process.
        for pid in reversed(candidates):
            try:
                LinuxProcessMemory._find_base(pid, name)
                return pid
            except (ProcessError, OSError):
                continue

        # Fallback: locate the executable through process mappings.
        for entry in entries:
            if not entry.name.isdecimal():
                continue

            try:
                pid = int(entry.name)
                LinuxProcessMemory._find_base(pid, name)
                return pid
            except (ProcessError, OSError):
                continue

        raise ProcessNotFound(
            f"Could not find a mapped process for {name}"
        )

    @staticmethod
    def _find_base(pid: int, name: str) -> int:
        """Find the image base from the executable's file-backed mappings."""
        maps_path = Path(f"/proc/{pid}/maps")
        matches = []

        try:
            for line in maps_path.read_text(
                errors="replace"
            ).splitlines():
                parts = line.split(maxsplit=5)
                if len(parts) < 6:
                    continue

                mapped_path = parts[5].removesuffix(" (deleted)")
                if Path(mapped_path).name.casefold() != name.casefold():
                    continue

                start_text, _end_text = parts[0].split("-", 1)
                file_offset = int(parts[2], 16)

                if file_offset == 0:
                    matches.append(int(start_text, 16))

        except (OSError, ValueError) as exc:
            raise ProcessError(
                f"Cannot inspect mappings for PID {pid}: {exc}"
            ) from exc

        if not matches:
            raise ProcessError(
                f"No file-backed image base found for {name} in PID {pid}"
            )

        return min(matches)

    @classmethod
    def open_process_from_name(cls, name: str):
        pid = cls._find_pid(name)
        base = cls._find_base(pid, name)
        return cls(pid, base)

    def _check_alive(self):
        if not Path(f"/proc/{self.process_id}").exists():
            raise ProcessError(f"Process {self.process_id} exited")

    def _validate_range(self, address: int, length: int):
        if not isinstance(address, int) or not isinstance(length, int):
            raise TypeError("Address and length must be integers")
        if address < 0 or length < 0:
            raise ValueError("Address and length must be non-negative")
        if address + length > 0x1_0000_0000:
            raise ValueError("Range exceeds the 32-bit address space")

        self._check_alive()

    def read_bytes(self, address: int, length: int) -> bytes:
        self._validate_range(address, length)
        try:
            return self._helper.read_bytes(address, length)
        except (OSError, RuntimeError, BrokenPipeError) as exc:
            raise ProcessError(f"Memory read failed: {exc}") from exc

    def write_bytes(self, address: int, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        self._validate_range(address, len(data))
        try:
            self._helper.write_bytes(address, data)
        except (OSError, RuntimeError, BrokenPipeError) as exc:
            raise ProcessError(f"Memory write failed: {exc}") from exc

    def read_short(self, address: int) -> int:
        return struct.unpack("<h", self.read_bytes(address, 2))[0]

    def write_short(self, address: int, value: int):
        self.write_bytes(address, struct.pack("<h", value))

    def read_int(self, address: int) -> int:
        return struct.unpack("<i", self.read_bytes(address, 4))[0]

    def write_int(self, address: int, value: int):
        self.write_bytes(address, struct.pack("<i", value))

    def close(self):
        helper = getattr(self, "_helper", None)
        if helper is not None:
            self._helper = None
            try:
                helper.close()
            except (OSError, RuntimeError):
                pass


class RabiRibiMemoryIO:
    """Linux counterpart to the existing Windows memory interface."""

    def __init__(self):
        self.rr_mem = None
        self.rr_process_id = None
        self.addr_injected_give_item_entrypoint = None

    def _disconnect(self):
        if self.rr_mem is not None:
            try:
                self.rr_mem.close()
            except (OSError, ProcessError):
                pass

        self.rr_mem = None
        self.rr_process_id = None
        self.addr_injected_give_item_entrypoint = None

    def is_connected(self):
        if self.rr_mem is None:
            return False

        try:
            self._read_int(OFFSET_AREA_ID)
            return True
        except (ProcessError, OSError, RuntimeError):
            logger.info("Lost connection with Rabi Ribi game.")
            self._disconnect()
            return False

    async def connect(self, exit_event: asyncio.Event):
        logger.info("Waiting for connection to Rabi Ribi game instance...")

        while not exit_event.is_set():
            try:
                self.rr_mem = LinuxProcessMemory.open_process_from_name(
                    "rabiribi.exe"
                )
                self.rr_process_id = self.rr_mem.process_id

                logger.info(
                    "Connected to Rabi Ribi (PID %s, base %s).",
                    self.rr_process_id,
                    hex(self.rr_mem.base_address),
                )
                return

            except ProcessNotFound:
                await asyncio.sleep(3)

            except (PermissionError, OSError, ProcessError, RuntimeError) as exc:
                self._disconnect()
                logger.warning("Cannot attach to Rabi Ribi: %s", exc)
                await asyncio.sleep(3)

    def allocate(self):
        raise NotImplementedError(
            "Linux remote executable allocation is not implemented."
        )

    def _read_word(self, offset):
        return self.rr_mem.read_bytes(
            self.rr_mem.base_address + offset, 4
        )

    def _read_short(self, offset):
        return self.rr_mem.read_bytes(
            self.rr_mem.base_address + offset, 2
        )

    def _read_byte(self, offset):
        return self.rr_mem.read_bytes(
            self.rr_mem.base_address + offset, 1
        )

    def _read_string(self, offset, length):
        return self.rr_mem.read_bytes(
            self.rr_mem.base_address + offset, length
        ).decode("utf-8", errors="replace")

    def _read_float(self, offset):
        return struct.unpack("<f", self._read_word(offset))[0]

    def _read_int(self, offset):
        return struct.unpack("<i", self._read_word(offset))[0]

    def _read_4_byte_bool(self, offset):
        return self._read_int(offset) != 0

    def _read_1_byte_bool(self, offset):
        return struct.unpack("<?", self._read_byte(offset))[0]

    def _read_4_byte_bool_raw(self, address):
        return struct.unpack(
            "<i", self.rr_mem.read_bytes(address, 4)
        )[0] != 0

    def read_player_tile_position(self):
        area_id = self._read_int(OFFSET_AREA_ID)
        x = round(self._read_float(OFFSET_PLAYER_X) / TILE_LENGTH)
        y = round(self._read_float(OFFSET_PLAYER_Y) / TILE_LENGTH)
        return area_id, x, y

    def read_tile_event_id(self, x: int, y: int):
        offset = OFFSET_EVENT_MAP + ((x * 200 + y) * 2)
        return struct.unpack("<h", self._read_short(offset))[0]

    def is_player_frozen(self):
        return (
            self._read_4_byte_bool(OFFSET_PLAYER_FROZEN)
            or not self._read_4_byte_bool(OFFSET_MAX_HEALTH)
            or self.is_player_paused()
        )

    def is_player_paused(self):
        return self._read_4_byte_bool(OFFSET_PLAYER_PAUSED)

    def is_in_item_receive_animation(self):
        return self._read_1_byte_bool(OFFSET_IN_ITEM_GET_ANIMATION)

    def is_near_crosswarp(self):
        _, px, py = self.read_player_tile_position()
        return any(
            241 <= self.read_tile_event_id(px + x, py + y) <= 251
            for x in range(-1, 2)
            for y in range(-1, 2)
        )


    def give_item(self, item_id: int):
        """Give an item through the game's native x86 function.

        Memory access is available on Linux, but calling the 32-bit game
        function requires a Wine-aware guest execution backend.
        """
        if not isinstance(item_id, int) or isinstance(item_id, bool):
            raise TypeError("item_id must be an integer")

        if not 0 <= item_id <= 0x7FFFFFFF:
            raise ValueError(f"Invalid item ID: {item_id}")

        if self.rr_mem is None:
            raise ProcessError("Not connected to Rabi-Ribi.")

        function_address = (
            self.rr_mem.base_address + OFFSET_GIVE_ITEM_FUNC
        )
        function_bytes = self.rr_mem.read_bytes(function_address, 16)

        expected_prologue = bytes.fromhex(
            "55 8b ec 83 ec 0c 83 3d 14 4a c8 00 00 53 56 8b"
        )
        if function_bytes != expected_prologue:
            raise ProcessError(
                "give_item target does not match the expected game function; "
                "refusing to execute an unverified address."
            )

        current_state = self.get_item_state(item_id)

        # Upgradeable items use inventory states 1, 2, and 3.
        # Preserve the disabled state if the item is currently disabled.
        item = data.get_item_by_id(item_id)
        max_state = 1 + item.max_upgrades

        if current_state == 0:
            new_state = 1
        elif current_state > 0:
            new_state = min(current_state + 1, max_state)
        elif current_state < 0:
            new_state = -min(abs(current_state) + 1, max_state)
        else:
            raise ProcessError(
                f"Unexpected inventory state {current_state} for item {item_id}"
            )

        self.set_item_state(item_id, new_state)

        actual_state = self.get_item_state(item_id)
        if actual_state != new_state:
            raise ProcessError(
                f"Failed to update item {item_id}: expected state "
                f"{new_state}, got {actual_state}"
            )

        return


    def remove_exclamation_point_from_in_memory_map(
        self, area_id, x, y
    ):
        address = (
            self.rr_mem.base_address
            + OFFSET_ITEM_MAP
            + ((x * 200 + y) * 2)
        )

        if self.rr_mem.read_short(address) == EXCLAMATION_POINT_ITEM_ID:
            self.rr_mem.write_short(address, 0)

    def remove_exclamation_point_from_inventory(self):
        self.set_item_state(EXCLAMATION_POINT_ITEM_ID, 0)

    def does_player_have_item_id(self, item_id) -> bool:
        return self._read_4_byte_bool(
            OFFSET_INVENTORY_START + 4 * int(item_id)
        )

    def get_item_state(self, item_id) -> int:
        return self._read_int(
            OFFSET_INVENTORY_START + 4 * int(item_id)
        )

    def set_item_state(self, item_id, state):
        self.rr_mem.write_int(
            self.rr_mem.base_address
            + OFFSET_INVENTORY_START
            + 4 * int(item_id),
            state,
        )

    def get_last_received_item_index(self):
        return self.get_item_state(UNUSED_ITEM_ID_48)

    def set_last_received_item_index(self, index):
        self.set_item_state(UNUSED_ITEM_ID_48, index)

    def set_event_state(self, event_id: int, state: bool):
        address = (
            self.rr_mem.base_address
            + OFFSET_EVENT_START
            + 4 * (event_id - EVENT_FLAG_ID_START)
        )
        self.rr_mem.write_int(address, 1 if state else 0)

    def open_warp_menu(self):
        base = self.rr_mem.base_address
        self.rr_mem.write_int(base + OFFSET_IN_WARP_MENU, 1)
        self.rr_mem.write_int(base + OFFSET_CURRENT_WARP_ID, -1)

    def get_collected_eggs(self) -> list[tuple[int, int, int]]:
        data = self.rr_mem.read_bytes(
            self.rr_mem.base_address + OFFSET_EGG_START,
            EGG_ARRAY_LENGTH,
        )
        eggs = list(struct.iter_unpack("<3h", data))

        if (0, 0, 0) in eggs:
            eggs = eggs[:eggs.index((0, 0, 0))]

        return eggs

    def get_number_of_eggs_collected(self) -> int:
        return len(self.get_collected_eggs())

    def is_on_correct_scenerio(self, scenerio_id: str) -> bool:
        return self._read_string(
            OFFSET_SCENERIO_INDICATOR, len(scenerio_id)
        ) == scenerio_id

    def is_on_main_menu(self) -> bool:
        return (
            not self._read_4_byte_bool(OFFSET_MAX_HEALTH)
            and not self.is_player_paused()
        )

    def is_in_save_menu(self) -> bool:
        return self._read_1_byte_bool(OFFSET_IN_SAVE_MENU)

    def is_in_warp_menu(self) -> bool:
        return self._read_4_byte_bool(OFFSET_IN_WARP_MENU)

    def is_in_costume_menu(self) -> bool:
        return self._read_4_byte_bool(OFFSET_IN_COSTUME_MENU)

    def has_zero_health(self) -> bool:
        player_state = struct.unpack(
            "<I", self._read_word(OFFSET_PLAYER_STATE)
        )[0]
        address = player_state + OFFSET_PLAYER_STATE_HEALTH
        return not self._read_4_byte_bool_raw(address)

    def set_player_health_to_zero(self):
        player_state = struct.unpack(
            "<I", self._read_word(OFFSET_PLAYER_STATE)
        )[0]
        address = player_state + OFFSET_PLAYER_STATE_HEALTH
        self.rr_mem.write_int(address, 0)
