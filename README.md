# EASM Platform (External Attack Surface Management)

Plateforme complète de gestion de la surface d'attaque externe, conçue pour automatiser la découverte, le scan et la surveillance des actifs exposés (domaines, sous-domaines, IPs, services) et détecter les vulnérabilités de sécurité.

## Fonctionnalités

*   **Reconnaissance & Découverte (Recon)** :
    *   **Énumération Passive** : Utilisation de **Subfinder** pour agréger les sous-domaines depuis de multiples sources publiques (OSINT) sans interagir directement avec la cible.
    *   **Résolution DNS** : Vérification active de l'existence des sous-domaines et résolution des adresses IP.
    *   **Gestion des Wildcards** : Détection et filtrage intelligent des environnements wildcard pour éviter les faux positifs.
    *   **Scope Management** : Définition précise des périmètres (domaines racines, exclusions) pour cibler uniquement les actifs autorisés.

*   **Scanning de Vulnérabilités** :
    *   **Port Scanning** : Scan ultra-rapide des ports via **Naabu** pour identifier les services exposés.
    *   **Vulnérabilités Web & Infra** : Orchestration de **Nuclei** avec des templates communautaires et personnalisés pour détecter :
        *   Mauvaises configurations (Headers, SSL/TLS).
        *   CVEs connues et critiques.
        *   Fichiers exposés et panels d'administration.
    *   **Sévérité** : Classification automatique des vulnérabilités (Info, Low, Medium, High, Critical).

*   **Gestion & Suivi (Dashboard)** :
    *   **Programmes** : Création et isolation des audits par "Programme" (ex: Bug Bounty, Client X, Interne).
    *   **Inventaire** : Vue centralisée de tous les actifs découverts (IPs, Domaines, Technologies détectées).
    *   **Suivi des Scans** : Monitoring en temps réel de l'avancement des tâches (Discovery, Port Scan, Vuln Scan).
    *   **Reporting** : Visualisation détaillée des vulnérabilités avec preuves (requête/réponse HTTP) et suggestions de remédiation.

*   **Architecture & Performance** :
    *   **Scalabilité** : Architecture distribuée avec files d'attente (**Redis**) et workers (**Celery**) permettant de scanner plusieurs cibles en parallèle.
    *   **Résilience** : Gestion automatique des échecs et relances (Retries).
    *   **Notifications** : Alerting en temps réel via Webhooks (Discord) lors de la découverte de vulnérabilités critiques.

## Architecture Technique

Le projet repose sur une architecture micro-services conteneurisée :

| Service | Technologie | Rôle |
| :--- | :--- | :--- |
| **Frontend** | React, Vite, TailwindCSS | Interface utilisateur SPA. |
| **Backend** | Python, FastAPI | API REST, logique métier, authentification JWT. |
| **Database** | PostgreSQL | Stockage persistant des données (relationnel). |
| **Broker** | Redis | File d'attente pour les tâches Celery et cache. |
| **Workers** | Python, Celery | Exécution des tâches de fond (scans). |
| **Monitoring** | Flower, Portainer | Supervision des workers et des conteneurs. |

## Prérequis

*   **Docker** et **Docker Compose** installés.
*   **Make** (optionnel mais recommandé pour utiliser les commandes simplifiées).

## Installation & Démarrage Rapide

La procédure a été simplifiée pour un démarrage en une seule commande.

1.  **Cloner le projet** :
    ```bash
    git clone https://github.com/RacineDuCiel/Projet-EASM.git
    cd Projet-EASM
    ```

2.  **Lancer l'installation automatique** :
    Cette commande construit les images, lance les conteneurs et initialise la base de données.
    ```bash
    make setup
    ```

    > **Note** : Si vous n'avez pas `make`, lancez manuellement :
    > ```bash
    > docker-compose up -d --build
    > # Attendre quelques secondes que la DB soit prête
    > docker-compose exec backend alembic upgrade head
    > ```

## Accès aux Services

Une fois l'installation terminée (`Setup complete!`), accédez aux différentes interfaces :

*   **Application Web (Frontend)** : [http://localhost:5173](http://localhost:5173)
*   **API Documentation (Swagger)** : [http://localhost:8000/docs](http://localhost:8000/docs)
*   **Supervision Workers (Flower)** : [http://localhost:5555](http://localhost:5555)
*   **Administration Docker (Portainer)** : [http://localhost:9000](http://localhost:9000)

## Commandes Utiles (Makefile)

Le fichier `Makefile` inclut des raccourcis pour la gestion quotidienne :

| Commande | Description |
| :--- | :--- |
| `make setup` | Premier lancement : Build, Up et Migrations DB. |
| `make up` | Démarre les conteneurs en arrière-plan. |
| `make down` | Arrête et supprime les conteneurs. |
| `make logs` | Affiche les logs de tous les services en temps réel. |
| `make migrate` | Joue les migrations de base de données (Alembic). |
| `make clean` | Nettoyage complet (arrête tout et supprime les volumes/images orphelins). |
| `make shell-backend` | Ouvre un terminal dans le conteneur backend. |

## Structure du Projet

*   `backend/` : Code source de l'API (FastAPI) et migrations Alembic.
*   `frontend/` : Code source de l'interface utilisateur (React).
*   `workers/` : Logique des scanners (Celery tasks).
*   `docker-compose.yml` : Définition de l'infrastructure.