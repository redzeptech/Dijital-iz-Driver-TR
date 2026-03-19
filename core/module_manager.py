"""
Modül Yönetim Sistemi
DFIR araçları için wrapper'ları dinamik olarak yükler ve yönetir.
"""

import importlib
import logging
from pathlib import Path
from typing import Any, Optional, Type

logger = logging.getLogger(__name__)


class BaseModule:
    """Tüm DFIR modülleri için temel sınıf."""

    name: str = "base"
    description: str = "Temel modül"
    required_tools: list[str] = []

    def __init__(self):
        self._validate_tools()

    def _validate_tools(self) -> bool:
        """Gerekli araçların sistemde mevcut olup olmadığını kontrol eder."""
        import shutil

        for tool in self.required_tools:
            if not shutil.which(tool):
                logger.warning(f"Araç bulunamadı: {tool}")
        return True

    def execute(
        self,
        evidence_path: Path,
        output_dir: Path,
        **kwargs: Any,
    ) -> dict:
        """
        Modülü çalıştırır.

        Args:
            evidence_path: Kanıt dosyası veya dizini
            output_dir: Çıktı dizini
            **kwargs: Modüle özel parametreler

        Returns:
            Çalıştırma sonucu (success, output_path, vb.)
        """
        raise NotImplementedError("Modüller execute() metodunu implement etmelidir.")

    def get_info(self) -> dict:
        """Modül bilgilerini döndürür."""
        return {
            "name": self.name,
            "description": self.description,
            "required_tools": self.required_tools,
        }


class ModuleManager:
    """Modül kayıt ve yükleme yöneticisi."""

    def __init__(self):
        self._modules: dict[str, Type[BaseModule]] = {}
        self._instances: dict[str, BaseModule] = {}
        self._load_builtin_modules()

    def _load_builtin_modules(self) -> None:
        """Yerleşik modülleri yükler."""
        builtin = ["volatility", "hayabusa", "kape", "ai_analyst", "chainsaw"]
        class_map = {"ai_analyst": "AIAnalystModule"}
        for name in builtin:
            try:
                mod = importlib.import_module(f"modules.{name}")
                class_name = class_map.get(name) or f"{name.title()}Module"
                module_class = getattr(mod, class_name, None) or getattr(mod, "Module", None)
                if module_class and issubclass(module_class, BaseModule):
                    self.register(name, module_class)
                    logger.info(f"Modül yüklendi: {name}")
            except ImportError as e:
                logger.debug(f"Modül yüklenemedi {name}: {e}")

        # cloud_wrapper.py → kayıt adı "cloud"
        try:
            cloud_mod = importlib.import_module("modules.cloud_wrapper")
            CloudCls = getattr(cloud_mod, "CloudForensicsModule", None)
            if CloudCls and issubclass(CloudCls, BaseModule):
                self.register("cloud", CloudCls)
                logger.info("Modül yüklendi: cloud (cloud_wrapper)")
        except ImportError as e:
            logger.debug(f"cloud_wrapper yüklenemedi: {e}")

        try:
            mob_mod = importlib.import_module("modules.mobile_wrapper")
            MobCls = getattr(mob_mod, "MobileForensicsModule", None)
            if MobCls and issubclass(MobCls, BaseModule):
                self.register("mobile", MobCls)
                logger.info("Modül yüklendi: mobile (mobile_wrapper)")
        except ImportError as e:
            logger.debug(f"mobile_wrapper yüklenemedi: {e}")

    def register(self, name: str, module_class: Type[BaseModule]) -> None:
        """Yeni modül kaydeder."""
        if not issubclass(module_class, BaseModule):
            raise TypeError(f"{module_class} BaseModule'dan türemelidir")
        self._modules[name] = module_class
        logger.debug(f"Modül kaydedildi: {name}")

    def get_module(self, name: str) -> Optional[BaseModule]:
        """Modül örneğini döndürür (singleton)."""
        if name not in self._modules:
            return None
        if name not in self._instances:
            self._instances[name] = self._modules[name]()
        return self._instances[name]

    def list_modules(self) -> list[dict]:
        """Kayıtlı tüm modüllerin bilgisini döndürür."""
        return [
            self.get_module(name).get_info()
            for name in self._modules
            if self.get_module(name)
        ]

    def unregister(self, name: str) -> bool:
        """Modülü kaldırır."""
        if name in self._modules:
            del self._modules[name]
            self._instances.pop(name, None)
            return True
        return False
