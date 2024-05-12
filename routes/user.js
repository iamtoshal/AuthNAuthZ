const express = require('express');

const router = express.Router();

const { login, signup } = require("../controllers/Auth");
const { auth, isStudent, isAdmin } = require("../middleware/auth");



router.post("/login", login);
router.post("/signup", signup);


//testing protected routes for simple middleware
router.get('/test', auth, (req, res) => {
    res.json({
        success: true,
        message: "Welcome to the Protected route for TESTS",
    });
})


//Protected Route
router.get("/student", auth, isStudent, (req, res) => {
    res.json({
        success: true,
        message: "Welcome to the Protected Route for students"
    });
});

router.get("/admin", auth, isAdmin, (req, res) => {
    res.json({
        success: true,
        message: "Welcome to Protected Route for Admin"
    });
});


module.exports = router;