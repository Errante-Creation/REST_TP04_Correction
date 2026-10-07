# TP4 Starter

Ce dossier fournit uniquement le point de départ. Les dépendances et les données de démonstration sont prêtes ; les mécanismes de sécurité sont intentionnellement absents.

## Démarrer

1. Dans ce dossier, exécuter `npm install`.
2. Copier `.env.example` vers `.env`.
3. Générer deux secrets JWT distincts et une clé AES de 32 octets encodée en Base64.
4. Exécuter `npm start`, puis vérifier `GET /health`.

## Travail à réaliser

1. Implémenter `encrypt` et `decrypt` dans `crypto_service.js` avec AES-256-GCM, un IV aléatoire de 16 octets et un tag vérifié.
2. Ajouter Helmet avec HSTS, `X-Frame-Options: DENY` et `X-Content-Type-Options: nosniff`.
3. Ajouter l'authentification JWT, puis une matrice RBAC pour `admin`, `auditor` et `user`.
4. Ajouter la connexion et le renouvellement : le refresh token doit être un cookie `HttpOnly`, `Secure`, `SameSite=Strict`.
5. Créer les routes de coordonnées bancaires chiffrées et la politique ABAC : un document clôturé ou modifié hors jours ouvrés (9 h–17 h, Paris) doit être refusé.

Ne placez jamais de secrets réels dans Git.
