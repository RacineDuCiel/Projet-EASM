RAPPORT D'AUDIT FINAL CONSOLIDÉ - PROJET EASM
3 agents | 148 fichiers analysés | 2026-02-08

Résumé Exécutif
L'architecture EASM (FastAPI + React + Celery + PostgreSQL) est solide dans ses fondamentaux (chiffrement Fernet, circuit breaker, rate limiting, séparation des responsabilités). Cependant, l'audit croisé des 3 agents révèle des failles de sécurité bloquantes pour la production, des problèmes de performance systémiques liés à l'eager loading SQLAlchemy et aux appels synchrones bloquants, et une UX incomplète avec des composants utilitaires créés mais jamais adoptés. Aucun test automatisé n'existe.

Domaine	Score	Critiques	Majeurs	Mineurs
Code & Bonnes Pratiques	5.5/10	6	12	13
UI & Expérience Utilisateur	5.5/10	5	10	12
Logique & Efficacité	5.5/10	4	10	12
GLOBAL	5.5/10	15	32	37
SPRINT 0 - SÉCURITÉ CRITIQUE (1-2 jours)
#	Fichier	Problème	Correctif
1	passive_intel.py:29-327	Tous POST+GET sans auth	Ajouter verify_worker_token (POST) et get_current_user (GET)
2	programs.py:20,88-106	POST/DELETE programmes sans auth	Ajouter get_current_user + check admin
3	scans.py:174,191,237	GET events/vulns/scan sans auth	Ajouter get_current_user
4	settings.py:99-107	SSRF via webhook URL utilisateur	Valider pattern https://discord.com/api/webhooks/*
5	config.py:12	Password superuser ChangeMe123! en dur	field_validator obligeant le changement
6	scans.py:119-120	Fuite d'erreurs internes str(e)	Message générique + log
7	docker-compose.yml:69	--reload en production	Retirer ou conditionner
8	docker-compose.yml:38,239	Credentials par défaut Redis/Flower	Variables d'env obligatoires
9	docker-compose.yml:10-11,43-44	Ports 5432/6379 exposés	Réseau Docker interne uniquement
SPRINT 1 - PERFORMANCE CRITIQUE (2-3 jours)
#	Fichier	Problème	Impact	Correctif
1	models/asset.py:35-49	13 relations lazy="selectin" sur Asset	100 assets = 1 + 13*batches requêtes	lazy="raise" + selectinload() explicite dans CRUD
2	models/program.py:55-57	Cascade eager : Programme→Scopes→Scans+Assets	Charge tout en mémoire	Idem
3	scan_service.py:315-317	celery.control.inspect() synchrone dans endpoint async	Bloque l'event loop entier	asyncio.to_thread()
4	monitoring.py:211-217	Même blocage + import incorrect src.celery_app	Event loop gelé	asyncio.to_thread() + corriger import
5	settings.py:102	requests.post() synchrone dans async	Bloque l'event loop 5s	httpx.AsyncClient
6	monitoring.py:25-102	7 COUNT séparées pour /stats	7 round-trips DB	Combiner en 1-2 requêtes CASE/WHEN
7	crud/passive_intel.py:116-124	SELECT individuel par enregistrement DNS (N+1)	50 DNS = 50 requêtes	WHERE IN batch
8	passive_intel.py:805-813	9 requêtes séquentielles pour get_full_passive_intel	9 round-trips	asyncio.gather() parallèle
9	scans.py:301-302	mark_assets_scanned : UPDATE individuel par asset	O(n) commits	Batch UPDATE + single commit
SPRINT 2 - LOGIQUE MÉTIER & STABILITÉ (2-3 jours)
#	Fichier	Problème	Correctif
1	scans.py (routes)	/profiles défini APRÈS /{scan_id} → intercepté comme UUID invalide	Déplacer /profiles avant /{scan_id}
2	endpoints/*.py	Comparaisons rôle : == "admin" (string) vs == UserRole.admin (enum)	Uniformiser UserRole.admin partout
3	scan_service.py:89-121	Pas de vérification de scan déjà actif sur le même scope	Ajouter verrou "1 scan actif par scope"
4	scan_service.py:241-300	resume_interrupted_scans ne vérifie pas si le scan est vraiment mort	Vérifier via Celery avant de relancer
5	scans.py:35-39 + vulnerabilities.py	Admins bloqués de lancer scans ET voir vulnérabilités	Permettre lecture admin globale
6	circuit_breaker.py:161,172	import asyncio après utilisation → NameError	Déplacer import en haut
7	circuit_breaker.py	5 breakers + 4 retry policies définis mais jamais utilisés	Intégrer ou supprimer
8	main.py:51	Base.metadata.create_all + ALTER TYPE au startup (conflit Alembic)	Se fier uniquement à Alembic
9	main.py:96-100	TrustedHostMiddleware avec allowed_hosts=["*"]	Configurer vrais domaines
10	Workers discovery	chord() sans limite → 5000 sous-domaines = 5000 tâches simultanées	chunks() de 50-100
SPRINT 3 - UI/UX (3-5 jours)
Corrections immédiates
#	Fichier	Correctif	Effort
1	index.html:5	<title>temp_app</title> → EASM Platform	Trivial
2	AssetsPage.tsx:61	colSpan={6} → colSpan={7}	Trivial
3	AssetsPage.tsx:20-26	Ajouter pagination serveur (charge tout sans limite)	Moyen
4	VulnerabilitiesPage.tsx	Ajouter contrôles pagination visibles	Moyen
5	ScansPage.tsx:34	Polling 5s permanent → conditionner aux scans actifs	Faible
6	AdminProgramsPage/Users	Polling 10s → invalidation après mutation	Faible
Adopter les composants communs existants
Composant inutilisé	Remplace	Pages concernées
SeverityBadge	Badges inline avec classes manuelles	VulnTable, AssetDetails, ScanDetails
LoadingSpinner (avec role="status")	<Loader2> sans accessibilité	Toutes les pages
EmptyState	États vides inline différents	Toutes les tables
Accessibilité
Composant	Problème	Correctif
ScanDetailsPage.tsx:175	En-têtes triables sans keyboard nav	role="button", tabIndex={0}, onKeyDown
ProfileSelector.tsx:67-111	Cartes cliquables sans sémantique radio	role="radiogroup" + role="radio" + aria-checked
AdminUsersPage.tsx:217	Suppression utilisateur sans confirmation	Ajouter AlertDialog
AdminUsersPage.tsx:142	<select> HTML natif au lieu de shadcn Select	Remplacer par Select shadcn
auth-store.ts:43-44	Refresh token ignoré → déconnexions fréquentes	Implémenter refresh automatique
SPRINT 4 - QUALITÉ & DETTE TECHNIQUE (5+ jours)
#	Catégorie	Action	Effort
1	Tests	Mettre en place pytest (backend) + vitest (frontend) + CI	Élevé
2	Refactoring	Découper tools.py (1879 lignes) en modules thématiques	Moyen
3	Code mort	Supprimer run_nuclei_with_tags dupliquée (lignes 715 vs 852)	Faible
4	Code mort	Supprimer lib/react-query.ts, CriticalityBadge non utilisés	Trivial
5	DB	Ajouter index sur Vulnerability.severity et .status	Faible
6	DB	Supprimer db.refresh() dupliqué dans crud/program.py:11-12	Trivial
7	Mémoire	Export CSV : StreamingResponse avec générateur paginé	Moyen
8	Mémoire	DiscordProvider : réutiliser httpx.AsyncClient (singleton)	Faible
9	Pydantic	Migrer @validator → @field_validator (v2) et .dict() → .model_dump()	Faible
10	Makefile	Target prod référence docker-compose.prod.yml supprimé	Trivial
Points Forts du Projet
Architecture bien séparée (backend/workers/frontend)
Chiffrement Fernet des API keys en base (EncryptedString)
Circuit breaker et retry patterns implémentés (même si non connectés)
Headers de sécurité HTTP complets
Rate limiting sur le login
Worker auth via token avec comparaison timing-safe (hmac.compare_digest)
Gestion structurée des exceptions (EASMBaseException)
Batch processing dans crud/asset.py (bonne pratique déjà appliquée)
Docker healthchecks + resource limits + no-new-privileges