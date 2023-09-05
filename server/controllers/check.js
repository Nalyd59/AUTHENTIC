const jwt = require('jsonwebtoken');
const KEY =  process.env.SECRET_KEY;


const extractBearer = authorization => {

    if(typeof authorization !== 'string'){
        return false
    }

    // On isole le token
    const matches = authorization.match(/(bearer)\s+(\S+)/i)

    return matches && matches[2]

}

const checkTokenMiddleware = (req, res, next) => {

    const token = req.headers.authorization && extractBearer(req.headers.authorization)

    if(!token){
        return res.status(401).json({ message: 'Ho le petit malin !!!'})
    }

    // Vérifier la validité du token
    jwt.verify(token, KEY, (err, decodedToken) => {
        if(err){
            return res.status(401).json({message: 'Bad token'})
        }

        next()
    })
}

module.exports = checkTokenMiddleware