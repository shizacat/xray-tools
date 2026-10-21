from __future__ import annotations

from typing import Dict

from pydantic import BaseModel


class BaseModelConfig(BaseModel):
    """
    Общая модель для всех конфигов
    """

    def model_dump(self, *args, **kwargs) -> Dict:
        """Return dump config

        Features:
          - exclude none
          - enum as value
        """
        kwargs.setdefault("exclude_none", True)
        # Ensures enums are dumped as values in python mode
        kwargs.setdefault("mode", "python")
        r = super().model_dump(*args, **kwargs)
        return r

    def model_dump_json(self, *args, **kwargs) -> str:
        """Return dump config as json"""
        kwargs.setdefault("exclude_none", True)
        return super().model_dump_json(*args, **kwargs)
