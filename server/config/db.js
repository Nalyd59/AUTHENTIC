require('dotenv').config();

const mysql = require('mysql');


const connectDb = async () => {
        try {
            const connection = await mysql.createConnection({
                host: process.env.DB_HOST,
                user: process.env.DB_USER,
                password: process.env.DB_PASSWORD,
                database: process.env.DB_NAME
            });
            console.log('Connexion à la base de données réussie!');
            return connection;
        } catch (err) {
            console.error('La connexion à la base de données a échoué : ' + err);
            throw err;
        }
}

module.exports = connectDb;