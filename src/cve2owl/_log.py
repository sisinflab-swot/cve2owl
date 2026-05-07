import csv
import logging
import sys
from pathlib import Path
from time import perf_counter_ns
from typing import Self

import psutil

_CUR_PROC = psutil.Process()


class ElapsedTime:
    @property
    def seconds(self) -> float:
        return self._seconds + self._nanos / 1_000_000_000

    @property
    def millis(self) -> float:
        return self.seconds * 1000 + self._nanos / 1_000_000

    def __init__(self) -> None:
        self._seconds = 0
        self._nanos = 0

    def add(self, nanos: int) -> None:
        self._nanos += nanos
        if self._nanos >= 1_000_000_000:
            self._seconds += self._nanos // 1_000_000_000
            self._nanos = self._nanos % 1_000_000_000


class MemPeak:
    @property
    def mb(self) -> float:
        return self.bytes / (1024 * 1024)

    def __init__(self) -> None:
        self.bytes = 0

    def update(self, val: int) -> None:
        self.bytes = max(self.bytes, val)


class RecordMetrics:
    @property
    def json_parse_time_ns(self) -> int:
        return self.json_parse_ts - self.start_ts

    @property
    def axiom_write_time_ns(self) -> int:
        return self.end_ts - self.json_parse_ts

    @property
    def elapsed_time_ns(self) -> int:
        return self.end_ts - self.start_ts

    def __init__(self, path: Path) -> None:
        self.name = path.stem
        self.input_bytes = path.stat().st_size
        self.output_bytes = 0
        self.axiom_count = 0
        self.rss = 0
        self.start_ts = perf_counter_ns()
        self.json_parse_ts = self.start_ts
        self.end_ts = self.start_ts

    def mark_axiom_written(self, written_bytes: int) -> None:
        self.axiom_count += 1
        self.output_bytes += written_bytes

    def mark_written(self, written_bytes: int) -> None:
        self.output_bytes += written_bytes

    def mark_json_parsed(self) -> None:
        self.json_parse_ts = perf_counter_ns()

    def mark_end(self) -> None:
        self.end_ts = perf_counter_ns()
        self.rss = _CUR_PROC.memory_info().rss


class Logger:
    def __init__(self) -> None:
        self._log = self._setup_logger()
        self._last_log_seconds = 0.0
        self._elapsed_time = ElapsedTime()
        self._mem_peak = MemPeak()
        self._record_count = 0
        self._input_bytes = 0
        self._output_bytes = 0
        self._axiom_count = 0
        self._record_metrics: RecordMetrics

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        del exc_type, exc_val, exc_tb
        self.end_record()

    def open(self, csv_path: Path | str) -> Self:
        self._csv_path = Path(csv_path)
        self._file = self._csv_path.open("w", encoding="utf-8", newline="")
        self._csv = csv.writer(self._file)
        self._csv.writerow([
            "record_name",
            "input_bytes",
            "output_bytes",
            "axiom_count",
            "json_parse_time_ns",
            "axiom_write_time_ns",
            "elapsed_time_ns",
            "rss_bytes",
        ])
        return self

    def close(self) -> None:
        self._file.close()
        self._log_info()

    def _setup_logger(self) -> logging.Logger:
        log = logging.getLogger("cve2owl")
        fmt = "[%(asctime)s] %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S"
        handler = logging.StreamHandler(sys.stdout)
        handler.formatter = logging.Formatter(fmt, datefmt=datefmt)
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        return log

    def _update_metrics(self) -> None:
        self._elapsed_time.add(self._record_metrics.elapsed_time_ns)
        self._mem_peak.update(self._record_metrics.rss)
        self._input_bytes += self._record_metrics.input_bytes
        self._output_bytes += self._record_metrics.output_bytes
        self._axiom_count += self._record_metrics.axiom_count
        self._record_count += 1

    def _log_metrics(self) -> None:
        self._csv.writerow([
            self._record_metrics.name,
            self._record_metrics.input_bytes,
            self._record_metrics.output_bytes,
            self._record_metrics.axiom_count,
            self._record_metrics.json_parse_time_ns,
            self._record_metrics.axiom_write_time_ns,
            self._record_metrics.elapsed_time_ns,
            self._record_metrics.rss,
        ])

    def _log_info(self) -> None:
        self._log.info(
            (
                "Records: %d, i_size: %.2f MB, o_size: %.2f MB, "
                "axioms: %d, time: %.2f s, mrss: %.2f MB"
            ),
            self._record_count,
            self._input_bytes / (1024 * 1024),
            self._output_bytes / (1024 * 1024),
            self._axiom_count,
            self._elapsed_time.seconds,
            self._mem_peak.mb,
        )

    def begin_record(self, path: Path) -> Self:
        self._record_metrics = RecordMetrics(path)
        return self

    def end_record(self) -> None:
        self._record_metrics.mark_end()
        self._update_metrics()
        self._log_metrics()

        if (cur_seconds := self._elapsed_time.seconds) - self._last_log_seconds >= 1.0:
            self._log_info()
            self._last_log_seconds = cur_seconds

    def mark_json_parsed(self) -> None:
        self._record_metrics.mark_json_parsed()

    def mark_axiom_written(self, written_bytes: int) -> None:
        self._record_metrics.mark_axiom_written(written_bytes)

    def mark_written(self, written_bytes: int) -> None:
        self._record_metrics.mark_written(written_bytes)

    def info(self, msg: str, *args: object) -> None:
        self._log.info(msg, *args)


logger: Logger = Logger()
