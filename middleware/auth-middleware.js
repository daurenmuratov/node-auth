const jwt = require('jsonwebtoken')

function verifyToken(req, res, next) {
    const token = req.cookies.token
    if (!token) {
        return res.status(401).send({
            message: 'Access Denied'
        })
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET)
        req.user = verified
        next()
    } catch (error) {
        res.status(400).send({
            message: 'Invalid Token'
        })
    }
}

module.exports = verifyToken