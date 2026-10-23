"""日志：单入口，方便统一格式与追加大盘。"""
from __future__ import annotations

import logging
import sys

_FMT = "%(asctime)s %(levelname)-5s %(name)s | %(message)s"


def get_logger(name: str = "redteam") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_FMT, datefmt="%H:%M:%S"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
