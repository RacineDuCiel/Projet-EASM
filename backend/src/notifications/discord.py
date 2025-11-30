import httpx
import os
import logging
from .base import NotificationProvider
from ..models import Vulnerability, Severity

logger = logging.getLogger(__name__)

class DiscordProvider(NotificationProvider):
    def __init__(self):
        self.webhook_url = os.getenv("DISCORD_WEBHOOK_URL")
        if not self.webhook_url:
            logger.warning("DISCORD_WEBHOOK_URL not configured. Notifications will not be sent.")

    async def send_alert(self, vulnerability: Vulnerability):
        if not self.webhook_url:
            logger.error("Cannot send Discord notification: DISCORD_WEBHOOK_URL is not configured")
            return

        # Couleurs selon sévérité
        color_map = {
            Severity.critical: 15158332, # Rouge
            Severity.high: 15105570,     # Orange
            Severity.medium: 16776960,   # Jaune
            Severity.low: 3447003,       # Bleu
            Severity.info: 9807270       # Gris
        }
        color = color_map.get(vulnerability.severity, 9807270)

        # Message générique sécurisé
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

        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(self.webhook_url, json=payload, timeout=10.0)
                response.raise_for_status()
                logger.info(f"Discord notification sent successfully for vulnerability: {vulnerability.title}")
            except httpx.HTTPError as e:
                logger.error(f"HTTP error sending Discord notification: {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Unexpected error sending Discord notification: {e}", exc_info=True)
