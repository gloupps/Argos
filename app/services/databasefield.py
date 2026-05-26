from dataclasses import dataclass, field
from typing import Any, List, Optional

@dataclass
class DatabaseField:
    name: str
    type: str  # label-capsule, label-color-bool, label-color-gradient, list, img
    value: Any

    icon: Optional[str] = None
    link: Optional[str] = None

    # depend of the type
    color: Optional[str] = None
    gradient: Optional[List[str]] = None
    max: Optional[int] = None  # list only