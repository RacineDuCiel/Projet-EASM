from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import database, models, schemas
from .auth import get_current_user
from ..notifications.discord import DiscordProvider

router = APIRouter(
    prefix="/notifications",
    tags=["notifications"]
)

@router.post("/test", status_code=status.HTTP_200_OK)
async def test_notification(
    current_user: models.User = Depends(get_current_user),
):
    """
    Envoie une fausse notification de vulnérabilité pour tester la configuration (Discord).
    """
    provider = DiscordProvider()
    
    if not provider.webhook_url:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="DISCORD_WEBHOOK_URL non configuré dans l'environnement."
        )

    # Création d'une fausse vulnérabilité pour le test
    fake_vuln = models.Vulnerability(
        title="TEST: Vulnérabilité de Test",
        severity=models.Severity.high,
        description="Ceci est une notification de test déclenchée manuellement par l'utilisateur.",
        status=models.VulnStatus.open
    )

    try:
        await provider.send_alert(fake_vuln)
        return {"message": "Notification de test envoyée avec succès."}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'envoi de la notification: {str(e)}"
        )
