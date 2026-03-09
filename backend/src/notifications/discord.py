import httpx
import os
import logging
from .base import NotificationProvider
from ..models import Vulnerability, Severity

logger = logging.getLogger(__name__)

# Module-level singleton httpx.AsyncClient for connection pooling.
# Reused across all DiscordProvider.send_alert() calls to avoid
# creating a new TCP connection per notification.
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    """Get or create the module-level httpx.AsyncClient singleton."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=10.0,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        )
    return _http_client


class DiscordProvider(NotificationProvider):
    def __init__(self):
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        if not self.webhook_url:
            logger.warning("DISCORD_WEBHOOK_URL not configured. Notifications will not be sent.")

    async def send_alert(self, vulnerability: Vulnerability):
        if not self.webhook_url:
            logger.error("Cannot send Discord notification: DISCORD_WEBHOOK_URL is not configured")
            return

        # Couleurs selon severite
        color_map = {
            Severity.critical: 15158332, # Rouge
            Severity.high: 15105570,     # Orange
            Severity.medium: 16776960,   # Jaune
            Severity.low: 3447003,       # Bleu
            Severity.info: 9807270       # Gris
        }
        color = color_map.get(vulnerability.severity, 9807270)

        # Message generique securise
        payload = {
            "username": "EASM Security Bot",
            "embeds": [{
                "title": f"Nouvelle Vulnérabilité {vulnerability.severity.value.upper()} !",
                "description": "Une nouvelle vulnérabilité a été détectée par le système de scan automatique.\\n\\n**Connectez-vous au dashboard pour consulter les détails et prendre les mesures nécessaires.**",
                "color": color,
                "footer": {
                    "text": "EASM Platform - Security Alert"
                }
            }]
        }

        client = _get_http_client()
        try:
            response = await client.post(self.webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Discord notification sent successfully for vulnerability: {vulnerability.title}")
        except httpx.HTTPError as e:
            logger.error(f"HTTP error sending Discord notification: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Unexpected error sending Discord notification: {e}", exc_info=True)
