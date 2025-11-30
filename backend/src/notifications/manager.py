from typing import List
from ..models import Vulnerability, Severity
from .discord import DiscordProvider

class NotificationManager:
    def __init__(self):
        self.providers = []
        # On ajoute Discord par défaut
        self.providers.append(DiscordProvider())

    async def notify_new_vulnerabilities(self, new_vulns: List[Vulnerability]):
        """
        Envoie une notification pour chaque nouvelle vulnérabilité critique ou haute.
        """
        for vuln in new_vulns:
            # On ne notifie que pour HIGH et CRITICAL
            if vuln.severity in [Severity.critical, Severity.high]:
                for provider in self.providers:
                    await provider.send_alert(vuln)
