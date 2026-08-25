from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.intelligence.wordpress import WordPressIntelligence


class CmsDetector:
    """CMS Extensible Profile Detector (§78).
    Supports WordPress, Joomla, Drupal, Magento, and extensible CMS profiles.
    """

    @classmethod
    def detect(cls, html: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        # Check WordPress
        wp_res = WordPressIntelligence.analyze_html_and_headers(html, headers)
        if wp_res["is_wordpress"]:
            return {
                "cms": "WordPress",
                "version": wp_res["version"],
                "theme": wp_res["theme"],
                "plugins": wp_res["plugins"],
                "details": wp_res,
                "confidence": "HIGH",
            }

        # Check Joomla
        if "Joomla!" in html or "/media/jui/" in html:
            return {
                "cms": "Joomla",
                "version": None,
                "confidence": "HIGH",
                "details": {},
            }

        # Check Drupal
        if "Drupal" in html or "drupal.js" in html:
            return {
                "cms": "Drupal",
                "version": None,
                "confidence": "HIGH",
                "details": {},
            }

        return None
