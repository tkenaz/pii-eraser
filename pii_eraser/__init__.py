"""pii-eraser: find personal data and secrets in text and replace them with
stable placeholders, locally, before the text goes anywhere."""

from pii_eraser.eraser import Eraser, ErasingSession, Stage
from pii_eraser.types import EraseResult, Kind, Span

__version__ = "0.1.0"

__all__ = ["Eraser", "ErasingSession", "Stage", "EraseResult", "Kind", "Span", "__version__"]
