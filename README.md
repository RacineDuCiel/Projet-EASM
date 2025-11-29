# Projet EASM (External Attack Surface Management)

Plateforme complète de gestion de la surface d'attaque externe. Ce projet permet de découvrir, scanner et surveiller les actifs exposés sur internet (sous-domaines, IPs, services) et de détecter les vulnérabilités potentielles.

## Architecture

Le projet est construit sur une architecture micro-services conteneurisée :

*   **Backend** : FastAPI (Python) - API REST, Gestion des données, Authentification JWT.
*   **Database** : PostgreSQL - Stockage persistant.
*   **Message Broker** : Redis - File d'attente pour les tâches asynchrones.
*   **Workers** : Celery (Python) - Exécution des scans en arrière-plan.
    *   `worker_discovery` : Tâches rapides (Subfinder, Orchestration).
    *   `worker_scan` : Tâches lourdes (Naabu, Nuclei).
*   **Monitoring** :
    *   **Flower** : Supervision des workers Celery.
    *   **Portainer** : Gestion des conteneurs Docker.

## Installation & Démarrage

Voici la procédure complète pour installer et lancer le projet depuis zéro.

### Prérequis
*   Docker & Docker Compose installés sur la machine.

### 1. Lancement de l'infrastructure
Construisez et lancez tous les conteneurs :

```bash
docker-compose up -d --build
```

### 2. Initialisation de la Base de Données (Migrations)
Une fois les conteneurs lancés, il faut jouer les migrations pour créer les tables (Users, Programs, Scans, etc.) :

```bash
docker-compose exec backend alembic upgrade head
```

### Accès aux Services

*   **API Backend (Swagger UI)** : [http://localhost:8000/docs](http://localhost:8000/docs)
*   **Monitoring Workers (Flower)** : [http://localhost:5555](http://localhost:5555)
*   **Administration Docker (Portainer)** : [http://localhost:9000](http://localhost:9000)