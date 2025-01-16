const User = require("../models/User")
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// register controller
const registerUser = async (req, res) => {
    try {
        // extract user information fro our request body
        const {username, email, password, role} = req.body;

        // check if the user is already exists in our database
        const checkExitingUser = await User.findOne({$or : [{username}, {email}]});
        if(checkExitingUser){
            return res.status(400).json({
                success : false,
                message : 'User is already exists with same username or same email. Please try with a diffrent username or email'
            });
        }

        // hash the user password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // created a new user and save in your database
        const newlyCreatedUser = new User({
            username,
            email,
            password : hashedPassword,
            role : role || 'user',
        });

        await newlyCreatedUser.save();

        if(newlyCreatedUser){
            res.status(201).json({
                success : true,
                message : 'User registered successfully!'
            });
        }else{
            res.status(400).json({
                success : false,
                message : 'Unable to user register, Please try again'
            })
        }

    } catch (error) {
        res.status(500).json({
            success : false,
            message : 'something error occured! Please try again',
        });
    }
}


// login controller
const loginUser = async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if the user exists in the database
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: `User doesn't exist!`,
            });
        }

        // Check if the password is correct
        const isPasswordMatch = await bcrypt.compare(password, user.password);

        if (!isPasswordMatch) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials!',
            });
        }

        // Create user token
        const accessToken = jwt.sign(
            {
                userId: user._id,
                username: user.username,
                role: user.role,
            },
            process.env.JWT_SECRET_KEY,
            {
                expiresIn: '15m',
            }
        );

        return res.status(200).json({
            success: true,
            message: 'Logged in successfully.',
            accessToken,
        });
    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred! Please try again.',
        });
    }
};



// Change Your Password
const changePassword = async (req, res) => {
    try {
        const userId = req.userInfo.userId;

        // extrqct old and new password
        const {oldPassword, newPassword} = req.body;

        // find the currect login In user
        const user = await User.findById(userId);

        if(!user){
            return res.status(400).json({
                success : false,
                message : 'User not found'
            })
        }

        // check if the old password is correct
        const isPasswordMatch = await bcrypt.compare(oldPassword, user.password);

        if(!isPasswordMatch){
            return res.status(400).json({
                success : false,
                message : 'Old Password is not correct! Please try again',
            });
        }

        // hash the password here
        const salt = await bcrypt.genSalt(10);
        const newHashedPassword = await bcrypt.hash(newPassword, salt);

        // update user password
        user.password = newHashedPassword;
        await user.save();

        res.status(200).json({
            success : true,
            message : 'Password changed successfully',
        })

    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred! Please try again.',
        });
    }
}

module.exports = {registerUser, loginUser, changePassword};