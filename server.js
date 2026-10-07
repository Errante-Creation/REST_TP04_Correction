'use strict';

const express = require('express');
const app = express();

// Socle volontairement réduit : les protections demandées par le TP restent à ajouter.
app.use(express.json({ limit: '16kb' }));

const documents = [
  { id: 1, ownerId: 'user-1', title: 'Dossier client', status: 'open' },
  { id: 2, ownerId: 'user-1', title: 'Dossier clôturé', status: 'closed' }
];

app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/api/v1/documents', (req, res) => res.json(documents));

// TODO 1 : ajouter Helmet et cookie-parser.
// TODO 2 : créer l'authentification JWT et la matrice RBAC admin/auditor/user.
// TODO 3 : exposer login/refresh avec un cookie HttpOnly, Secure, SameSite=Strict.
// TODO 4 : chiffrer les coordonnées bancaires avec crypto_service.js.
// TODO 5 : empêcher une modification hors heures ouvrées ou d'un document closed.

const port = process.env.PORT || 3005;
if (require.main === module) {
  app.listen(port, () => console.log(`TP4 démarré sur http://localhost:${port}`));
}

module.exports = app;
