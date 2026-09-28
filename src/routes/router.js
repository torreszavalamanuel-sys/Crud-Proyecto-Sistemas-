const express = require('express')
const router = express.Router()
const authController = require('../controllers/authController')

// Rutas de Vistas
router.get('/', authController.isauthenticated, (req, res) => {
    res.render('index', { user: req.user })
})

router.get('/login', (req, res) => {
    res.render('login', { alert: false })
})

router.get('/register', (req, res) => {
    res.render('register')
})

router.get('/register2', (req, res) => {
    res.render('register2')
})

// Rutas CRUD Usuarios
router.get('/users', authController.isauthenticated, authController.getUsers)
router.get('/edit-user/:id', authController.isauthenticated, authController.editUserView)
router.post('/update-user', authController.isauthenticated, authController.updateUser)
router.get('/delete-user/:id', authController.isauthenticated, authController.deleteUser)

// Métodos de autenticación
router.post('/register', authController.register)
router.post('/login', authController.login)
router.get('/logout', authController.logout)

module.exports = router