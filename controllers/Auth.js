const bcrypt = require('bcrypt');
const User = require('../model/User');
const jwt = require("jsonwebtoken");
const { options } = require('../routes/user');

require('dotenv').config();

//signup
exports.signup = async (req, res) => {
    try {
        //get data
        const { name, email, password, role } = req.body;

        //check if user already exist
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already Exists"
            })
        }

        //secure password
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        }
        catch (err) {
            res.status(500).json({
                success: false,
                message: "Error in hashing password"
            })
        }

        //create entry for user
        const user = await User.create({
            name, email, password: hashedPassword, role
        });

        return res.status(200).json({
            sucess: true,
            message: "User created successfully"
        })

    }
    catch (err) {
        console.error(err);
        return res.status(500).json({
            sucess: false,
            message: "User cannot be registered, Please try again later"
        })

    }
}



exports.login = async (req, res) => {
    try {
        //data fetch
        const { email, password } = req.body;

        //validation on email and password
        if (!email || !password) {
            return res.status(400).json({
                sucess: false,
                message: "Please fill all the details carefully"
            });
        }

        //check for registered user
        let user = await User.findOne({ email });

        //if not a registered user
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "User is not registered"
            })
        }


        //payload or body
        const payload = {
            email: user.email,
            id: user._id,
            role: user.role
        };

        //verify password and generate JWT token
        if (await bcrypt.compare(password, user.password)) {
            //Password match
            let token = jwt.sign(payload,
                process.env.JWT_SECRET,
                {
                    expiresIn: '2h'
                }
            );

            user = user.toObject();
            user.token = token;
            user.password = undefined;
            console.log(user);

            const options = {
                expiresIn: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true,
            }

            res.cookie("token", token, options).status(200).json({
                success: true,
                token,
                user,
                message: "User Logged in successfully"
            });


        } else {
            //password do not match
            return res.status(403).json({
                success: false,
                message: "Password Incorrect"
            })
        }



    } catch (err) {
        console.log(err)
        return res.status(500).json({
            success: false,
            message: "Login Failure"
        })

    }
}
