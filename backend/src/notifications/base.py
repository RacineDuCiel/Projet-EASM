from abc import ABC, abstractmethod
from ..models import Vulnerability

class NotificationProvider(ABC):
    @abstractmethod
    async def send_alert(self, vulnerability: Vulnerability):
        """
        Envoie une alerte pour une vulnérabilité donnée.
        """
        pass
