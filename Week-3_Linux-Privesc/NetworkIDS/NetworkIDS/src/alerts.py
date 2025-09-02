import datetime
import sys

class AlertSink:
    def __init__(self, log_path: str | None = None):
        self.log_path = log_path
        self._fh = open(log_path, "a", buffering=1, encoding="utf-8") if log_path else None

    def close(self):
        if self._fh:
            self._fh.close()

    def _emit(self, level: str, msg: str):
        ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        line = f"[{ts}] {level} {msg}"
        print(line)
        if self._fh:
            self._fh.write(line + "\n")

    def info(self, msg: str):
        self._emit("INFO", msg)

    def warn(self, msg: str):
        self._emit("WARN", msg)

    def alert(self, msg: str):
        self._emit("ALERT", msg)