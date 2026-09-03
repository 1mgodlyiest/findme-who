"""
findme-who: High-speed passive B2B lead enrichment & OSINT engine (SpiderFoot Distilled)
"""

from .engine import enrich_domain, enrich_batch

__version__ = "1.0.0"
__all__ = ["enrich_domain", "enrich_batch"]
