const router = require('express').Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const verifyToken = require('../middleware/auth-middleware')
const { set } = require('mongoose')


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

router.post('/monitoring', verifyToken, async (req, res) => {
    try {
        const axios = require('axios');
        const cheerio = require('cheerio');

        const response = await axios.get('https://trumploto.club/portal/index.php');
        const data = response.data;

        // Load data into Cheerio
        const $ = cheerio.load(data);

        // Get input values by name
        let timestamp = $('input[name="timestamp"]').val();
        let timestamp_md5 = $('input[name="timestamp_md5"]').val();

        // Timeout 5 seconds
        await new Promise(r => setTimeout(r, 5000))
        let setCookieHeader = response.headers['set-cookie'];

        // Send POST request to trumploto.club/portal/auth.php
        await axios.post('https://trumploto.club/portal/auth.php', {
                timestamp: timestamp,
                timestamp_md5: timestamp_md5,
                email: 'ObllbO',
                passw: '12345678',
            },
            {
                withCredentials: true,
                headers: {
                    'Cookie': setCookieHeader,
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            }
        )

        const monitorResponse = await axios.post('https://trumploto.club/portal/monitor_out.php', {
                update_option: 'on',
                search: '',
                filter_account: 'all',
            },
            {
                withCredentials: true,
                headers: {
                    'Cookie': setCookieHeader,
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            }
        )

        trimmedData = monitorResponse.data['table'].replace(/[\n\r\t]/g, '').trim()
        const $table = cheerio.load(trimmedData)

        // table foreach th get text
        let tableHeader = []
        $table('th').each((i, th) => {
            if (i == 0 || (i >= 2 && i <= 12))
                tableHeader.push($table(th).text().replace(/ /g, '\n'))
        })

        // table foreach without last row  tr>td get text
        let tableData = []
        $table('tr').each((i, tr) => {
            let row = []
            $table(tr).find('td').each((j, td) => {
                if (j == 0 || (j >= 2 && j <= 12))
                    row.push($table(td).text().replace(/ /g, '\n').replace(/\.00/g, '.00 ').replace(/\.../g, ''));
            })
            if (row.length > 0)
                tableData.push(row)
        })

        lastRow = tableData.pop()
        let tableFooter = []
        if (lastRow.length == 7) {
            let row = []
            lastRow.forEach((td, i) => {
                row.push(td);
            })
            tableFooter.push(row)
        }

        res.send({ message: 'Success', tableHeader, tableData, tableFooter})
    } catch (e) {
        console.error(e)
        return res.status(400).send({
            message: 'Error'
        })
    }
})

module.exports = router
