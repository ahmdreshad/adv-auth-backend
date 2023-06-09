const User = require('../models/userModel')
const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')

// protect /////
const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token
    if (!token) {
      res.status(401)
      throw new Error('Not authorized token, Please log in')
    }

    // verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET)

    // get user id from token
    const user = await User.findById(verified.id).select('-password')

    if (!user) {
      res.status(400)
      throw new Error('User not found')
    }
    if (user.role === 'suspended') {
      res.status(400)
      throw new Error('User suspended, Please contact support')
    }
    req.user = user
    next()
  } catch (error) {
    res.status(401)
    throw new Error('Not authorized user, Please log in')
  }
})

// admin /////
const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as an admin')
  }
})

// author /////
const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user.role === 'author' || req.user.role === 'admin') {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized as an author or admin')
  }
})

// verified ///
const verifiedOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next()
  } else {
    res.status(401)
    throw new Error('Not authorized, Account not verified')
  }
})

module.exports = { protect, adminOnly, authorOnly, verifiedOnly }
