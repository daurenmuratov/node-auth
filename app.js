require('dotenv').config();
const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const cors = require('cors')
const cookieParser = require('cookie-parser')
const routes = require('./routes/routes')
const path = require('path')
const { open } = require('sqlite')
const multer = require('multer')

const PORT = process.env.PORT || 3000
const dbFilePath = path.join(__dirname, './test.db')

// Multer setup for file storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads')
    },
    filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
    },
})

const upload = multer({ storage: storage })

const connect_db = async () => {
    try {
        db = await open({
            filename: dbFilePath,
            driver: sqlite3.Database
        })
        console.log(`Database Connected: ${dbFilePath}`)
    } catch (error) {
        console.log(`Database Connection Failed: ${error.message}`)
        process.exit(1)
    }
}

app = express()

app.use(cookieParser())

app.use(cors({
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    origin: [
        'http://localhost:3000',
        'http://localhost:8080',
        'https://localhost:4200',
        'http://localhost:5173',
    ]
}))

app.use(express.json())
app.use(express.urlencoded({ extended: true })) // To handle URL-encoded data

// Pass multer instance to routes
app.use((req, res, next) => {
    req.upload = upload
    next()
})

app.use('/api', routes)

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack)
    res.status(500).send({ message: 'Server Error', error: err.message })
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    connect_db()
})
