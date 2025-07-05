import os
import csv
import requests
import pandas as pd

from typing import Protocol, Optional, Dict, Any, List


class OutputWriter(Protocol):
    def write(self, data: Dict[str, Any]) -> None:
        """Write a single record to the sink."""
        ...

    def close(self, delete_file: bool = False) -> None:
        """Clean up resources and optionally delete file (if disk-based)."""
        ...


class CSVWriter:
    """
    CSVWriter supports:
      - Disk mode (output_file: str): writes rows to CSV on disk.
      - In-memory mode (output_file: None): buffers in memory, use .to_dataframe().
    """

    def __init__(self, output_file: Optional[str]) -> None:
        self.output_file: Optional[str] = output_file
        self._line: int = 0

        if output_file is None:
            self._buffer: List[Dict[str, Any]] = []
            self._file = None
            self._writer = None
        else:
            os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
            self._file = open(output_file, "w", newline="")
            self._writer = csv.writer(self._file)

    def write(self, data: Dict[str, Any]) -> None:
        if self.output_file is None:
            self._buffer.append(data)
        else:
            if self._line == 0:
                self._writer.writerow(list(data.keys()))
            self._writer.writerow(list(data.values()))
            self._file.flush()
        self._line += 1

    def to_dataframe(self) -> pd.DataFrame:
        if self.output_file is not None:
            raise RuntimeError("to_dataframe() is only valid for in-memory mode.")
        if not hasattr(self, "_buffer") or not self._buffer:
            return pd.DataFrame()
        return pd.DataFrame(self._buffer)

    def close(self, delete_file: bool = False) -> None:
        """Close file and optionally delete if it's a disk-backed writer."""
        if self.output_file is not None and getattr(self, "_file", None):
            try:
                self._file.close()
            except Exception:
                pass
            if delete_file:
                try:
                    os.remove(self.output_file)
                except FileNotFoundError:
                    pass
                except Exception as e:
                    print(f"⚠️ Failed to delete file: {e}")
        # If in-memory, just clear the buffer
        if self.output_file is None and hasattr(self, "_buffer"):
            self._buffer.clear()

    def __getstate__(self) -> Dict[str, Any]:
        state = self.__dict__.copy()
        state.pop("_file", None)
        state.pop("_writer", None)
        return state

    def __setstate__(self, state: Dict[str, Any]) -> None:
        self.__dict__.update(state)
        if self.output_file is not None:
            os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
            self._file = open(self.output_file, "a+", newline="")
            self._writer = csv.writer(self._file)

    def __del__(self) -> None:
        self.close()


class HttpWriter:
    """
    Posts each record (dict) to a given URL as JSON.
    """

    def __init__(self, output_url: str) -> None:
        self.url: str = output_url
        self.session = requests.Session()

    def write(self, data: Dict[str, Any]) -> None:
        self.session.post(self.url, json=data)

    def close(self, delete_file: bool = False) -> None:
        """Close the HTTP session."""
        try:
            self.session.close()
        except Exception:
            pass

    def __del__(self) -> None:
        self.close()


def output_writer_factory(
    output_mode: str,
    output: Optional[str]
) -> OutputWriter:
    """
    Factory for OutputWriter implementations:
      - output_mode = 'csv' → returns CSVWriter
      - output_mode = 'url' → returns HttpWriter
    """
    match output_mode:
        case "csv":
            return CSVWriter(output)
        case "url":
            if output is None:
                raise ValueError("Must provide a URL for 'url' mode")
            return HttpWriter(output)
        case _:
            raise ValueError(f"Unsupported output_mode: {output_mode}")