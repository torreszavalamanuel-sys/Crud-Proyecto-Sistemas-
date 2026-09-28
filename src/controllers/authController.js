const jwt = require('jsonwebtoken')
const bcryptjs = require('bcryptjs')
const conexion = require('../database/db')
const { promisify } = require('util')

// Registrar usuario
exports.register = async (req, res) => {
    try {
        const name = req.body.name
        const email = req.body.email
        const password = req.body.password

        let passHash = await bcryptjs.hash(password, 8)
        
        conexion.query('INSERT INTO users SET ?', { email: email, name: name, password: passHash }, (error, results) => {
            if (error) { 
                console.log("Error al registrar:", error) 
                return res.redirect('/register')
            }
            res.redirect('/users')
        })
    } catch (error) {
        console.log("Error en try-catch register:", error)
        res.redirect('/register')
    }
}

// Iniciar sesión
exports.login = async (req, res) => {
    try {
        const email = req.body.email
        const password = req.body.password

        if (!email || !password) {
            return res.render('login', {
                alert: true,
                alertTitle: "Advertencia",
                alertMessage: "Ingrese un email y password",
                alertIcon: 'info',
                showConfirmButton: true,
                timer: false,
                ruta: 'login'
            })
        }

        conexion.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
            if (error) {
                console.log("Error en consulta login:", error)
                return res.render('login', {
                    alert: true,
                    alertTitle: "Error",
                    alertMessage: "Error de conexión a la base de datos",
                    alertIcon: 'error',
                    showConfirmButton: true,
                    timer: false,
                    ruta: 'login'
                })
            }

            if (!results || results.length == 0 || !(await bcryptjs.compare(password, results[0].password))) {
                return res.render('login', {
                    alert: true,
                    alertTitle: "Error",
                    alertMessage: "Usuario y/o Password incorrectos",
                    alertIcon: 'error',
                    showConfirmButton: true,
                    timer: false,
                    ruta: 'login'
                })
            }

            // Login Correcto
            const id = results[0].id
            const token = jwt.sign({ id: id }, process.env.JWT_SECRETO, {
                expiresIn: process.env.JWT_TIEMPO_EXPIRA
            })

            const cookiesOptions = {
                expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
                httpOnly: true
            }
            res.cookie('jwt', token, cookiesOptions)
            return res.render('login', {
                alert: true,
                alertTitle: "Conexion exitosa",
                alertMessage: "¡LOGIN CORRECTO!",
                alertIcon: 'success',
                showConfirmButton: false,
                timer: 800,
                ruta: 'users'
            })
        })
    } catch (error) {
        console.log("Error en try-catch login:", error)
    }
}

// Middleware de autenticación
exports.isauthenticated = async (req, res, next) => {
    if (req.cookies && req.cookies.jwt) {
        try {
            const decodificada = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRETO)
            conexion.query('SELECT * FROM users WHERE id = ?', [decodificada.id], (error, results) => {
                if (!results || results.length == 0) {
                    return res.redirect('/login')
                }
                req.user = results[0]
                return next()
            })
        } catch (error) {
            console.log("Error en verificación JWT:", error)
            return res.redirect('/login')
        }
    } else {
        res.redirect('/login')
    }
}

// Mostrar lista de usuarios
exports.getUsers = (req, res) => {
    conexion.query('SELECT * FROM users', (error, results) => {
        if (error) {
            console.log("Error al consultar usuarios:", error)
            return res.render('users', { user: req.user, users: [] })
        }
        res.render('users', { user: req.user, users: results })
    })
}

// Mostrar vista para editar un usuario
exports.editUserView = (req, res) => {
    const id = req.params.id
    conexion.query('SELECT * FROM users WHERE id = ?', [id], (error, results) => {
        if (error || results.length === 0) {
            return res.redirect('/users')
        }
        res.render('edit-user', { user: req.user, editUser: results[0] })
    })
}

// Guardar cambios del usuario editado
exports.updateUser = async (req, res) => {
    const id = req.body.id
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password

    if (password && password.trim() !== '') {
        const passHash = await bcryptjs.hash(password, 8)
        conexion.query('UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?', [name, email, passHash, id], (error) => {
            if (error) console.log("Error al actualizar con pass:", error)
            res.redirect('/users')
        })
    } else {
        conexion.query('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, id], (error) => {
            if (error) console.log("Error al actualizar sin pass:", error)
            res.redirect('/users')
        })
    }
}

// Eliminar usuario
exports.deleteUser = (req, res) => {
    const id = req.params.id
    conexion.query('DELETE FROM users WHERE id = ?', [id], (error) => {
        if (error) console.log("Error al eliminar usuario:", error)
        res.redirect('/users')
    })
}

// Cerrar sesión
exports.logout = (req, res) => {
    res.clearCookie('jwt')
    return res.redirect('/login')
}