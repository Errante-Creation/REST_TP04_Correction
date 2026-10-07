'use strict';

const express = require('express');
const helmet = require('helmet')
const cookieParser = require('cookie-parser')
const { z } = require('zod')
const jwt = require('jsonwebtoken')
const app = express();

// Socle volontairement réduit : les protections demandées par le TP restent à ajouter.
app.use(express.json({ limit: '16kb' }));
// Middleware chargeant les cookies envoyés par le client req.cookies
app.use(cookieParser())

// Helmet centralise les en-têtes 
app.use(helmet({
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true 
  },
  frameguard: {
    action: 'deny',
    noSniff: true
  }
}))

const REFRESH_COOKIE = 'refreshToken'; // Nom du cookie HTTP contenant le refreshToken
const REFRESH_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/api/v1/auth/refresh',
  maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
};

// Pour supprimer le cookie, express demande les mêmes attributs de portée, sans maxAge
const REFRESH_CLEAR_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  path: '/api/v1/auth/refresh',
};

const documents = [
  { id: 1, ownerId: 'user-1', title: 'Dossier client', status: 'open' },
  { id: 2, ownerId: 'user-1', title: 'Dossier clôturé', status: 'closed' }
];

const Login = z.object({
  email: z.string().email().trim().toLowerCase(),
  password: z.string().min(1).max(200)
}).strict();

const Users = z.array(z.object({
  id: z.string().min(1),
  email: z.string().email(),
  role: z.enum(['admin', 'auditor', 'user']),
  passwordHash: z.string().min(10)
}))

// Fonction utilitaire pour charger et valider la longueur minimale d'une clé secrète
function secret(name){
  const value = process.env[name]; 

  if(!value || Buffer.byteLength(value) < 32)
    throw new Error(`${name} doit contenir au moins 32 octets`)

  return value;
}
// Génère et signe un jeton JWT (access ou refresh)
function token(user, type){
  return jwt.sign({
      sub: user.id,
      role: user.role,
      tokenUse: type
    },
    secret(
      type === 'access' ? 'JWT_ACCESS_SECRET' : 'JWT_REFRESH_SECRET'
    ),
    {
      expiresIn: type === 'access' ? '15m' : '7d',
      algorithm: 'HS256'
    }
  )
}

// Inject le cookie HTTP-Only


// Fonction qui extrait et valide les utilisateurs qui sont configurés dans TP4_USERS_JSON
function users(){
  const parsed = Users.safeParse(JSON.parse(process.env.TP4_USERS_JSON || '[]'))

  if(!parsed.success) throw new Error('Data invalide')

  return parsed.data;
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Endpoint d'authentification par identifiant et mot de passe
app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const input = Login.safeParse(req.body) // Valide le format de données reçues via Zod
    if(!input.success) return res.status(422).json({title: 'Identifiants invalides', status: 422})

      // Recherche l'utilisateur correspondant dans la liste
      const user = users().find(entry => entry.email === input.data.email);
      if(!user || !(await bcrypt.compare(input.data.password, user.passwordHash)))
        return res.status(401).json({title: 'Identifiants invalides', status: 401})

      // On émet le refreshToken sous forme de cookie sécurisé HTTP-Only


  } catch (error) {
    next(error)
  }
})


app.get('/api/v1/documents', (req, res) => res.json(documents));

// TODO 2 : créer l'authentification JWT et la matrice RBAC admin/auditor/user.
// TODO 3 : exposer login/refresh avec un cookie HttpOnly, Secure, SameSite=Strict.
app.post('/api/v1/auth/refresh', (req, res)=> {
  // Gérer la validation avec JWT

  // Gérer les permissions
})
// TODO 4 : chiffrer les coordonnées bancaires avec crypto_service.js.
// TODO 5 : empêcher une modification hors heures ouvrées ou d'un document closed.

const port = process.env.PORT || 3005;
if (require.main === module) {
  app.listen(port, () => console.log(`TP4 démarré sur http://localhost:${port}`));
}

module.exports = app;
