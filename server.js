'use strict';

const express = require('express');
const helmet = require('helmet')
const cookieParser = require('cookie-parser')
const { z } = require('zod')
const jwt = require('jsonwebtoken');
const { encrypt, decrypt } = require('./crypto_service');
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

// Matrice des permissions associée à chaque rôle utilisateur (contrôle d'accès RBAC)
const PERMISSIONS = {
  admin: ['bank:create', 'bank:read:any', 'document:update:any'],
  auditor: ['bank:read:any'],
  user: ['bank:create', 'bank:read:own', 'document:update:own']
}

// Stockage en mémoire des données bancaires chiffrées
const bankDetails = [];
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

const Bank = z.object({
  iban: z.string().trim().min(15).max(34)
}).strict()

const Update = z.object({
  title: z.string().min(2).max(120)
}).strict()

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
function refreshCookie(res, value){
  res.cookie(
    REFRESH_COOKIE,
    value,
    REFRESH_OPTIONS
  )
}

// Générateur de middleware pour le contrôle d'accés basé sur les rôles (RBAC)
function requirePermission(...needed){
  return (req, res, next) => 
    needed.some(permission => PERMISSIONS[req.user.role].includes(permission)) ?
    next() :
    res.status(403).json({title: 'Permission refusée', status: 403}) 
}


// Fonction qui extrait et valide les utilisateurs qui sont configurés dans TP4_USERS_JSON
function users(){
  const parsed = Users.safeParse(JSON.parse(process.env.TP4_USERS_JSON || '[]'))

  if(!parsed.success) throw new Error('Data invalide')

  return parsed.data;
}

// Middleware d'authentification vérifie le jeton porteur (Bearer token)
function authenticate(req, res, next){
  const match = /^Bearer ([^\s]+)$/i.exec(req.get('authorization') || ''); // Extrait le token depuis l'entête Authorization HTTP

  if(!match) return res.Status(401).json({title: 'Jeton requis', status: 401});

  try {
    const payload = jwt.verify(match[1], secret('JWT_ACCESS_SECRET'), { algorithms: ['HS256']}) // Vérifie la signature cryptographique du jeton

    if(payload.tokenUse !== 'access' || !PERMISSIONS[payload.role] || !payload.sub)
      throw new Error('Claims invalides')

    // attache les claims validé de l'utilisateur à l'objet de requête
    req.user = payload;
    next();
  } catch  {
    res.Status(401).json({title: 'Jeton invalide', status: 401});
  }
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
      refreshCookie(res, token(user, 'refresh'))
      res.json({
        accessToken: token(user, 'access'),
        expiresIn: 900 // Renvoie l'access token signé valable 15 minutes
      })
  } catch (error) {
    next(error)
  }
})

// Enpoint de renouvellement des jetons à partir du cookie de refresh
app.post('/api/v1/auth/refresh', (req, res) => {
  try {
    const payload = jwt.verify(req.cookies[REFRESH_COOKIE] || '', secret('JWT_REFRESH_SECRET'), {
      algorithms: ['HS256']
    });

    // Vérifie que c'est bien un refresh token et que les claims sont conformes
    if(payload.tokenUse !== 'refresh' || !PERMISSIONS[payload.role] || typeof payload.sub !== 'string')
      throw new Error('Jeton invalide')

    const user = {
      id: payload.sub,
      role: payload.role
    }

    // Effectuer une rotation du refresh token tout en renvoyant un nouveau cookie
    refreshCookie(res, token(user, 'refresh'))
    res.json({ accessToken: token(user, 'access'), expiresIn: 900 })
  } catch {
    res.clearCookie(REFRESH_COOKIE, REFRESH_CLEAR_OPTIONS)
    res.status(401).json({title: 'Refresh token invalide ou expiré', status: 401})
  }
})



// TODO 4 : chiffrer les coordonnées bancaires avec crypto_service.js.
// Enpoint de création de coordonnées bancaire avec contrôle RBAC
app.post('/api/v1/bank-details', authenticate, requirePermission('bank:create'), (req, res) => {
  // Valider le format de l'IBAN avec Zod
  const input = Bank.safeParse(req.body);
  if(!input.success) return res.status(422).json({title: 'IBAN invalide', status: 422})

  // Chiffre l'IBAN au repos avec AES-256-GCM AVANT stockage
  const record = {
    id: bankDetails.length + 1,
    ownerId: String(req.user.sub),
    encrypted: encrypt(input.data.iban)
  };
  // Sauvegarde l'enregistrement avec le payload chiffré
  bankDetails.push(record);
  res.status(201).json({id: record.id, status: 'encrypted'})
})

app.get('/api/v1/bank-details/:id', authenticate, requirePermission('bank:read:any', 'bank:read:own'), (req, res) => {
  // Recherche l'enregistrement bancaire demandé par son identifiant
  const record = bankDetails.find(entry => entry.id === Number(req.params.id))

  if(!record) return res.status(404).json({title: 'Enregistrement introuvable', status: 404});

  // Applique la règle RBAC/ABAC : Un utilisateur simple ne peut lire que ses propres données
  if(req.user.role === 'user' && record.ownerId !== String(req.user.sub))
    return res.status(403).json({title: 'Accès refusé', status: 403})

  // Déchiffre l'IBAN à la volée avec vérification d'intégrité et le renvoie
  res.json({
    id: record.id,
    iban: decrypt(record.encrypted)
  })
})

// Fonction qui détermine si on se trouve dans les heures ouvrés
function withinBusinessHours(date = new Date()){
  // Formate l'heure et le jour dans le fuseau Euroe/Paris
  const parts = new Intl.DateTimeFormat('fr-FR', { 
    timeZone: 'Europe/Paris', 
    weekday: 'short',
    hour:'2-digit',
    hourCycle: 'h23'
  }).formatToParts(date)

    // Transforme les parties formatées en objet clé-valeur
    const value = Object.fromEntries(parts.map(part => [part.type, part.value]));

    // Valide si le jour est entre lundi et vendredi et entre 09:00 et 16:59
    return ['Lun.', 'Mar.', 'Mer.', 'Jeu.', 'Ven.'].includes(value.weekday) &&
    Number(value.hour) >= 9 && Number(value.hour) < 17;
}

// Endpoint de mise à jour d'un document avec ABAC
app.patch('/api/v1/documents/:id', authenticate, requirePermission('document:update:own', 'document:update:any'), (req, res) => {
  const input = Update.safeParse(req.body)

  const document = documents.find(entry => entry.id === Number(req.params.id))
  if(!input.success) return res.status(422).json({title: 'Données sont invalides', status: 422 })

  if(!document) return res.status(404).json({ title: 'Document introuvable', status: 404})

  // Vérifie si l'utilisateur est ADMIN ou PROPRIÉTAIRE du document
  const canUpdate = req.user.role === 'admin' || document.ownerId === String(req.user.sub)

  if(!canUpdate || document.status == 'closed' || !withinBusinessHours()) 
    return res.status(403).json({title: 'Modification interdite par la politique ABAC', status: 403});

  document.title = input.data.title;
  res.json(document);

});

// TODO 5 : empêcher une modification hors heures ouvrées ou d'un document closed.
// Middleware global de capture et traitement des erreurs Express
app.use((error, req, res, next) => {
  // Délègue si les en-têtes de réponse ont déjà été envoyés au client
  if(res.headersSent) return next(error)

  console.error(error.message);

  res.status(500).json({title: 'Erreur interne', status: 500})
})

const port = process.env.PORT || 3005;
if (require.main === module) {
  app.listen(port, () => console.log(`TP4 démarré sur http://localhost:${port}`));
}

module.exports = app;
