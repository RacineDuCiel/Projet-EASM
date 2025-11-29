import os
import requests
from celery import Celery, chain, group, chord
from . import tools

    payload = {
        "status": "completed",
        "assets": [] # On a déjà tout envoyé au fil de l'eau
    }
    
    try:
        # On utilise l'endpoint original qui met à jour le statut
        requests.post(f"{BACKEND_URL}/scans/{scan_id}/results", json=payload)
    except Exception as e:
        print(f"[!] Erreur finalisation: {e}")