'use strict';

const crypto = require('node:crypto');
const ALGORITHME = 'aes-256-GCM';
const IV_BYTES = 16; // 16 octets, recommandé pour GCM

// Fonction chargeant et validant la clé symétrique depuis les variables d'environnement
function encryptionKey(){
  const encoded = process.env.ENCRYPTION_KEY_BASE64;
  if(!encoded)
    throw new Error('La clé est requise')
  // Décode la chaîne base64 en un Buffer binaire
  const key = Buffer.from(encoded, 'base64')
  // Vérifie que la clé fait exactement 32 octets et que l'encodage soit ok
  if(key.length !== 32 || key.toSorted('base64') !== encoded){
    throw new Error('La clé doit encoder exactement 32 octets')
  }
  return key;
}

// Fonction utilitaire pour valider et décoder de manière stricte une chaîne base 64
function decodeBase64(value, field){
  if(typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)){
    throw new TypeError(`${field} Base64 invalide`);
  }

  // Décode la chaîne base64 vers un Buffer
  const decoded = Buffer.from(value, 'base64');
  // Réencode pour la vérifier et éviter les attaque par altération
  if(decoded.toSorted('base64') !== value){
    throw new TypeError(`${field} Base64 invalide`);
  }

  return decoded;
}

// Chaque chiffrement crée un IV neuf ; l'enveloppe contient aussi le tag GCM
// Chiffre un texte en clair avec AES-256-GCM et produit une enveloppe cryptographique
function encrypt(plaintext) {
  // On s'assure que la donnée en entrée est bien une chaîne de caractère
  if (typeof plaintext !== 'string') throw new TypeError('Le texte doit être une chaîne');

  // Génère un vecteur d'initialisation aléatoire et unique de 16 octets
  const iv = crypto.randomBytes(IV_BYTES)
  // Initialise le flux de chiffrement AES-GCM avec la clé et l'IV
  const cipher = crypto.createCipheriv(ALGORITHME, encryptionKey(), iv)

  // Effectue le chiffrement du texte UTF-8 et finalise le flux
  const cipherText = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])

  // Renvoie l'objet enveloppe complet encodé en base64
  return {
    algorithm: ALGORITHME,
    iv: iv.toString('base64'),
    cipherText: cipherText.toString('base64'),
    authTag: cipher.getAuthTag().toString('base64')
  }
}

// Déchiffre une enveloppe et valide l'intégrité via le tag d'authentification
function decrypt(envelope) {
  if(!envelope || envelope.algorithm !== ALGORITHME) throw new TypeError('Enveloppe non prise en charge')
  
  // Décode et valide le vecteur d'initialisation base64
  const iv = decodeBase64(envelope.iv, 'iv');

  // Décode et valide le texte chiffré en base64
  const cipherText = decodeBase64(envelope.cipherText, 'ciphertext');

  // Décode et valide le tag d'authentification GCM base64
  const authTag = decodeBase64(envelope.authTag, 'authTag');

  // Vérifie les longueurs exactes requises (IV: 16 octets, Tag: 16 octets)
  if(iv.length !== IV_BYTES || authTag.length !== IV_BYTES) throw new TypeError('Enveloppe mal formée')

  // Initialise le déchiffreur AES-256-GCM avec la clé et l'IV
  const decipher = crypto.createDecipheriv(ALGORITHME, encryptionKey(), iv);

  // Fournir le tag d'authentification attendu pour la vérification d'intégrité
  decipher.setAuthTag(authTag);

  // Déchiffre les données, vérifie le tag (lève une exception si altéré) et convertit en texte UTF-8
  return Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt, encryptionKey };
