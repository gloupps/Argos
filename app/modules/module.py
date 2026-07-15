from abc import ABC, abstractmethod
from typing import List, Dict, Any


class Module(ABC):

    name:            str  = ""
    description:     str  = ""
    src_type:        str  = "external"   # external | internal | siem
    supported_types: list = []
    icon:            str  = "box"
    url:             str  = ""
    # Certains modules internes acceptent Basic Auth ou aucune auth
    # (ex: EsInstanceModule) — mettre False pour ne pas bloquer l'exécution
    # sur l'absence de api_keys[mod_key] dans services.py.
    requires_api_key: bool = True

    # Optional extra settings fields (non-key config, e.g. instance URLs).
    # Each entry: { key, type, label, placeholder }
    # Supported types: "url", "text"
    settings_fields: list = []

    @abstractmethod
    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def get_fields(self) -> Dict[str, Any]:
        return {
            "key":             self._key(),
            "name":            self.name,
            "description":     self.description,
            "type":            self.src_type,
            "icon":            self.icon,
            "url":             self.url,
            "supported_types": self.supported_types,
            "correlation":     self.get_correlation_fields(),
            "settings_fields": self.settings_fields,
        }

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return []

    def _key(self) -> str:
        return self.name.lower().replace(" ", "_")
