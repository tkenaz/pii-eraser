"""The one interface every detector implements."""

from typing import List, Protocol

from pii_eraser.types import Span


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> List[Span]:
        """Return candidate spans with absolute offsets into `text`."""
        ...
