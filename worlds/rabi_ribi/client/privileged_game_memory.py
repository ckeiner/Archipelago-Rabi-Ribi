import subprocess


class PrivilegedGameMemory:
    def __init__(self, pid: int):
        self.process = subprocess.Popen(
            [
                "sudo", "-n",
                "/usr/local/libexec/rabi-ribi-memory-helper",
                str(pid),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )

        if self.process.stdout is None or self.process.stdin is None:
            self.close()
            raise RuntimeError("Could not initialize memory helper")

        response = self.process.stdout.readline().strip()
        if response != "READY":
            self.close()
            raise RuntimeError(
                f"Memory helper failed to initialize: {response!r}"
            )

    def read_bytes(self, address: int, length: int) -> bytes:
        if not 0 <= length <= 4096:
            raise ValueError("Read length must be between 0 and 4096")

        assert self.process.stdin is not None
        assert self.process.stdout is not None

        self.process.stdin.write(f"R {address:x} {length}\n")
        self.process.stdin.flush()

        response = self.process.stdout.readline().strip()
        if not response.startswith("OK "):
            raise RuntimeError(f"Memory read failed: {response}")

        data = bytes.fromhex(response[3:])
        if len(data) != length:
            raise RuntimeError(
                f"Expected {length} bytes, received {len(data)}"
            )
        return data

    def write_bytes(self, address: int, data: bytes) -> None:
        if len(data) > 4096:
            raise ValueError("Write length must not exceed 4096 bytes")

        assert self.process.stdin is not None
        assert self.process.stdout is not None

        self.process.stdin.write(f"W {address:x} {data.hex()}\n")
        self.process.stdin.flush()

        response = self.process.stdout.readline().strip()
        expected = f"OK {len(data)}"
        if response != expected:
            raise RuntimeError(f"Memory write failed: {response}")

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None:
            return

        if process.poll() is None:
            try:
                if process.stdin is not None:
                    process.stdin.write("Q\n")
                    process.stdin.flush()
                process.wait(timeout=2)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        self.process = None