const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const conn = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
const EMAIL =  process.env.EMAIL_ADMIN;
const KEY =  process.env.SECRET_KEY;

/*
let pass = "okay";
let salt = bcrypt.genSalt(10);
let hash = bcrypt.hash(pass, salt);
let compare = bcrypt.compare(pass, hash);
*/

// Register a new user
const createUser = (req, res) => {
    // Utilise req.body de body-parser
    const { mail, password } = req.body;
    // Vérifier si les champs sont remplis
    if (!mail || !password) {
        return res.status(400).json({
            error: 'Email ou mot de passe manquant',
        });
    }
    if (mail == EMAIL) {
        return res.status(400).json({
            error: 'Email deja utilisée',
        });
    }
    // Vérifier si les mdp avec les regex
    const passwordRegexMAJ = /[A-Z]/g;
    const passwordRegexMIN = /[a-z]/g;
    const passwordRegexNUM = /[1-9]/g;
    const passwordRegexSPE = /[^a-zA-Z\d]/g;
    let errorMessage = 'Le mot de passe doit contenir';

    if (!passwordRegexMAJ.test(password)) {
        return res.status(400).json({
            error: errorMessage + ' une majuscule.',
        });
    }
    if (!passwordRegexMIN.test(password)) {
        return res.status(400).json({
            error: errorMessage + ' une lettre en minuscule.',
        });
    }
    if (!passwordRegexNUM.test(password)) {
        return res.status(400).json({
            error: errorMessage + ' au moins un chiffre.',
        });
    }
    if (!passwordRegexSPE.test(password)) {
        return res.status(400).json({
            error: errorMessage + ' au moins un caractère spécial.',
        });
    }
    // Cryptage du password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        const query = 'INSERT INTO `admin` (`mail`, `password`) VALUES ( ?, ?)';
        conn.query(query, [mail, hashedPassword], (dbErr) => {
            if (dbErr) {
                return res.status(500).json({ error: dbErr.message });
            } else {
                res.status(200).json({ message: 'Utilisateur enregistré' });
            }
        });
    });
};

// Connexion admin 
const signUp = (req, res) => {
    const { mail, password } = req.body;

    // Vérifier si les champs sont remplis
    if (!mail || !password) {
        return res.status(400).json({ error: 'Email et mot de passe sont requis' });
    }
    
    const query = 'SELECT * FROM `admin` WHERE `mail` = ?';

    conn.query(query, [mail], (dbErr, results) => {
        if (dbErr) {
            return res.status(500).json({ error: dbErr.message });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Utilisateur non trouvé' });
        }

        const admin = results[0];

        bcrypt.compare(password, admin.password, (bcryptErr, result) => {
            if (bcryptErr) {
                return res.status(500).json({ error: 'Erreur de comparaison de mot de passe' });
            }

            if (!result) {
                return res.status(401).json({ error: 'Mot de passe incorrect' });
            }

            // Le mot de passe est correct, générer un token JWT
            jwt.sign({ payload: { mail: EMAIL } }, KEY, (jwtErr, token) => {
                if (jwtErr) {
                    return res.status(500).json({ error: 'Erreur de génération du token JWT' });
                }
                res.status(200).json({ token });
            });
        });
    });
};



// Dashboard
const dashboard = (req, res, next) => {
    
    const extractBearer = authorization => {

        if(typeof authorization !== 'string'){
            return false
        }
    
        // On isole le token
        const matches = authorization.match(/(bearer)\s+(\S+)/i)
    
        return matches && matches[2]
    
    }

    const tokenTest = req.headers.authorization && extractBearer(req.headers.authorization);
    
    if (!tokenTest) {
        return res.status(401).json({ error: 'Accès non autorisé. Le jeton JWT est manquant.' });
    }

    jwt.verify(tokenTest, KEY, (verifyErr, decoded) => {
        if (verifyErr) {
            // Le token n'est pas valide, l'utilisateur n'est pas authentifié
            return res.status(401).json({ error: 'Token JWT non valide' });
        }
        next()
    });
};


module.exports = {
    signUp,
    createUser,
    dashboard
};