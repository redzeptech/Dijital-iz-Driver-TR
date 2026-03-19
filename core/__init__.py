"""
Dijital İz Sürücü - Core Engine
DFIR Framework'ün ana motoru ve araç koordinasyonu.
"""

from .engine import DFIREngine
from .module_manager import ModuleManager
from .utils import normalize_event, normalize_events_batch
from .masking import mask_data, mask_event, mask_structure
from .reporter import (
    DEFAULT_CASE_TITLE,
    DEFAULT_INCIDENT_RESPONSE_TITLE,
    DEFAULT_EVIDENCE_MATRIX,
    generate_html_report,
    generate_pdf_report,
)
from .context_engine import (
    ENTITY_TYPE_IP,
    EntityCard,
    build_ip_entity_index,
    export_entity_index_json,
    get_ip_entity_card,
    load_results_bundle,
    normalize_ipv4,
)

__all__ = [
    "DFIREngine",
    "ModuleManager",
    "normalize_event",
    "normalize_events_batch",
    "mask_data",
    "mask_event",
    "mask_structure",
    "DEFAULT_CASE_TITLE",
    "DEFAULT_INCIDENT_RESPONSE_TITLE",
    "DEFAULT_EVIDENCE_MATRIX",
    "generate_html_report",
    "generate_pdf_report",
    "ENTITY_TYPE_IP",
    "EntityCard",
    "build_ip_entity_index",
    "export_entity_index_json",
    "get_ip_entity_card",
    "load_results_bundle",
    "normalize_ipv4",
]
