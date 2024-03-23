require('dotenv').config();
const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const cors = require('cors')
const cookieParser = require('cookie-parser')
const routes = require('./routes/routes')
const path = require('path')
const { open } = require('sqlite')


const PORT = process.env.PORT || 3000
const dbFilePath = path.join(__dirname, './test.db')


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
app.use('/api', routes)

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
    connect_db()
})
