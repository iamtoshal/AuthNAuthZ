//auth ,isStudent,isAdmin

const jwt = require('jsonwebtoken');

require('dotenv').config();

exports.auth = (req, res, next) => {
    try {
        //extract JWT token
        //PENDING :other ways to fetch tojen
        const token = req.body.token;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Token missing"
            })
        }

        //verify the token
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET);
            console.log("Decoded token value", payload);

            req.user = payload;

        } catch (error) {
            return res.status(401).json({
                success: false,
                message: "Token is invalid"
            })

        }

        next();

    } catch (err) {
        return res.status(401).json({
            success: false,
            message: "Something went wrong while verifying token",
        })

    }
}


exports.isStudent = (req, res, next) => {
    try {
        if (req.user.role !== "Student") {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for student"
            })
        }

        next();

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "User Role is not matching",
        })

    }
}

exports.isAdmin = (req, res, next) => {
    try {
        if (req.user.role !== "Admin") {
            return res.status(401).json({
                success: false,
                message: "This is a protected route for Admin"
            })
        }

        next();

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "User Role is not matching"
        })

    }
}
