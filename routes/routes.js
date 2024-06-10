const router = require('express').Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const verifyToken = require('../middleware/auth-middleware')


const MAX_FILE_SIZE = 1024 * 1024 * 5 // 5MB

router.get('/', verifyToken, async (req, res) => {
    res.send('Welcome to the authentication API!')
})

router.post('/register', async (req, res) => {
    const { name: username, email, password } = req.body
    let query = `SELECT * FROM users WHERE username = '${username}' OR email = '${email}`
    let result = await db.get(query);
    if (result) {
        return res.status(400).send({
            message: 'User already exists'
        })
    }

    if (password.length < 8) {
        return res.status(400).send({
            message: 'Password is too short'
        })
    }

    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(req.body.password, salt)
    let insertUserQuery = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${hashedPassword}')`
    await db.run(insertUserQuery);
    return res.send({
        message: 'Success'
    })
})

router.post('/login', async (req, res) => {
    const { username, password } = req.body
    let query = `SELECT * FROM users WHERE username = '${username}'`
    let result = await db.get(query);
    if (result === undefined) {
        return res.status(404).send({
            message: 'User not found'
        })
    }

    if (!await bcrypt.compare(password, result.password)) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    const token = jwt.sign({_id: result.id}, process.env.JWT_SECRET)
    res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 1000 * 60 * 60 * 24
    })
    return res.send({
        message: 'Success'
    })
})

router.patch('/change-password', verifyToken, async (req, res) => {
    let { username, oldPassword, newPassword } = req.body
    let query = `SELECT * FROM users WHERE username = '${username}'`
    let result = await db.get(query);
    const validPassword = await bcrypt.compare(oldPassword, result.password)
    if (!validPassword) {
        return res.status(400).send({
            message: 'Invalid credentials'
        })
    }

    if (newPassword.length < 8) {
        return res.status(400).send({
            message: 'Password is too short'
        })
    }

    let newPasswordHash = await bcrypt.hash(newPassword, 10)
    let updatePasswordQuery = `UPDATE users SET password = '${newPasswordHash}' WHERE username = '${username}'`
    await db.run(updatePasswordQuery);
    return res.send({
        message: 'Success'
    })
})

router.post('/logout', verifyToken, async (req, res) => {
    res.cookie('token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        expires: new Date(0)
    })

    return res.send({
        message: 'Success logout'
    })
})

router.get('/users', verifyToken, async (req, res) => {
    try {
        let query = `SELECT * FROM users`
        let response = await db.all(query)
        response.forEach(user => {
            delete user.password
        })
        return res.send(response)
    } catch (e) {
        return res.status(401).send({
            message: 'Not authorized'
        })
    }
})

router.post('/upload', verifyToken, (req, res) => {
    console.log('Upload route hit') // Logging for debug
    req.upload.single('file')(req, res, function (err) {
        if (err) {
            console.error('File upload error:', err) // Logging for debug
            return res.status(400).send({ message: 'File upload failed', error: err.message })
        }
        if (!req.file) {
            console.log('No file uploaded') // Logging for debug
            return res.status(400).send({ message: 'No file uploaded' })
        }
        if (req.file.size > MAX_FILE_SIZE) {
            console.log('File too large') // Logging for debug
            return res.status(400).send({ message: 'File size exceeds the maximum limit of 5MB' })
        }
        console.log('File uploaded successfully', req.file) // Logging for debug
        res.send({ message: 'Success', file: req.file })
    })
})

module.exports = router
