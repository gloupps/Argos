from abc import ABC, abstractmethod
from typing import List, Dict, Any


class Module(ABC):

    name: str = ""
    description: str = ""
    src_type: str = ""  # internal / external / siem
    supported_types: list = []
    icon: str = ""
    url: str = ""

    # -------------------------
    # DATA COLLECTION
    # -------------------------
    @abstractmethod
    def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Retourne des lignes prêtes à être stockées en DB
        """
        pass

    # -------------------------
    # CORRELATION
    # -------------------------
    @abstractmethod
    def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Retourne des relations entre indicateurs
        """
        pass

    # -------------------------
    # QUOTAS API
    # -------------------------
    @abstractmethod
    def get_quotas(self) -> Dict[str, Any]:
        pass

    # -------------------------
    # UI CONFIG
    # -------------------------
    def get_fields(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.type,
            "icon": self.icon,
            "url": self.url,
            "correlation": self.get_correlation_fields()
        }

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return []