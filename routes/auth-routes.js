const express = require('express');
const { registerUser, loginUser, changePassword} = require('../controllers/auth-controller');
const authMiddleware = require('../middleware/auth-middleware');
const router = express.Router();


// all routes are related to authentication and authorization

// register route
router.post('/register', registerUser);


// login route
router.post('/login', loginUser)

// Change Password
router.post('/change-password', authMiddleware, changePassword);



module.exports = router;