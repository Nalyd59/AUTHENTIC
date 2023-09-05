const router = require('express').Router();
const authController = require('../controllers/auth.controller');
const checkTokenMiddleware = require('../controllers/check')

router.post('/register', authController.createUser);
router.post('/login', authController.signUp);
router.get('/dashboard', checkTokenMiddleware, (req,res) =>{
    res.status(200).json({message : 'ok'})
});

module.exports = router;
