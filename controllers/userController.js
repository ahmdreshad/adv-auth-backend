const jwt = require('jsonwebtoken')
const User = require('../models/userModel')
const Token = require('../models/tokenModel')
const Cryptr = require('cryptr')
const bcrypt = require('bcryptjs')
const parser = require('ua-parser-js')
const crypto = require('crypto')
const sendEmail = require('../utils/sendEmail')
const asyncHandler = require('express-async-handler')
const { generateToken, hashToken } = require('../utils/index')
const { OAuth2Client } = require('google-auth-library')

const cryptr = new Cryptr(process.env.CRYPTR_KEY)

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

// Register user /////////////////////////
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body

  // validation
  if (!name || !email || !password) {
    res.status(400)
    throw new Error('Please fill in all the required fields')
  }

  if (password.length < 6) {
    res.status(400)
    throw new Error('Password must be at least 6 characters')
  }

  // check if user exists
  const userExist = await User.findOne({ email })

  if (userExist) {
    res.status(400)
    throw new Error('User already exists, Please log in')
  }

  // get user agent
  const ua = parser(req.headers['user-agent'])
  const userAgent = [ua.ua]

  // create user
  const user = await User.create({
    name,
    email,
    password,
    userAgent,
  })

  // Generate Token
  const token = generateToken(user._id)

  // send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: 'none',
    secure: true,
  })

  if (user) {
    const { _id, name, email, phone, photo, bio, role, isVerified } = user

    res.status(201).json({
      _id,
      name,
      email,
      phone,
      photo,
      bio,
      role,
      isVerified,
      token,
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data')
  }
})

// Login user /////////////////////////
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  // validation
  if (!email || !password) {
    res.status(400)
    throw new Error('Please enter your email and password')
  }

  // check if user exists
  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error('User not found, Please sign up')
  }

  // check if password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password)
  if (!passwordIsCorrect) {
    res.status(400)
    throw new Error('Invalid email or password')
  }

  // Trigger two factor athentication for unknown users or browsers

  // get user agent
  const ua = parser(req.headers['user-agent'])
  const thisUserAgent = ua.ua

  const allowedAgent = user.userAgent.includes(thisUserAgent)

  if (!allowedAgent) {
    // Genrate 6 digit code
    const loginCode = Math.floor(Math.random() * 900000 + 100000)
    console.log(loginCode)

    // Encrypt login code before saving to DB
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString())

    // Delete Token if it exists in DB
    let userToken = await Token.findOne({ userId: user._id })
    if (userToken) {
      await userToken.deleteOne()
    }

    //   // Save Token to DB
    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
    }).save()

    res.status(400)
    throw new Error('New browser or device detected')
  }
  // generare token
  const token = generateToken(user._id)

  if (user && passwordIsCorrect) {
    // send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: 'none',
      secure: true,
    })

    const { _id, name, email, phone, photo, bio, role, isVerified } = user
    res.status(200).json({
      _id,
      name,
      email,
      phone,
      photo,
      bio,
      role,
      isVerified,
      token,
    })
  } else {
    res.status(400)
    throw new Error('Invalid email or password')
  }
})

// Logout user ////////////////////////
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie('token', '', {
    path: '/',
    httpOnly: true,
    expires: new Date(0), // expires it immediately
    sameSite: 'none',
    secure: true,
  })
  return res.status(200).json({
    message: 'Logged out successfully',
  })
})

// Get single user /////////////////////
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id)

  if (user) {
    const { _id, name, email, phone, photo, bio, role, isVerified } = user
    res.status(200).json({
      _id,
      name,
      email,
      phone,
      photo,
      bio,
      role,
      isVerified,
    })
  } else {
    res.status(400)
    throw new Error('Invalid email and password')
  }
})

// update user //////////////////////////
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id)

  if (user) {
    const { name, email, phone, photo, role, bio, isVerified } = user

    user.email = email
    user.name = req.body.name || name
    user.phone = req.body.phone || phone
    user.photo = req.body.photo || photo
    user.bio = req.body.bio || bio

    const updateUser = await user.save()

    res.status(200).json({
      _id: updateUser._id,
      name: updateUser.name,
      email: updateUser.email,
      phone: updateUser.phone,
      photo: updateUser.photo,
      bio: updateUser.bio,
      role: updateUser.role,
      isVerified: updateUser.isVerified,
    })
  } else {
    res.status(404)
    throw new Error('User not found')
  }
})

// delete user /////////////////////////
const deleteUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id)

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }
  await user.deleteOne()

  res.status(200).json({
    message: 'User deleted successfully',
  })
})

// get all users ///////////////////////
const getUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort('-createdAt').select('-password')

  if (!users) {
    res.status(500)
    throw new Error('Something went wrong')
  }

  res.status(200).json(users)
})

// login status ////////////////////////
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token

  if (!token) {
    return res.json(false)
  }

  const verified = jwt.verify(token, process.env.JWT_SECRET)
  if (verified) {
    return res.json(true)
  }
  return res.json(false)
})

// upgrade user ////////////////////////
const upgradeUser = asyncHandler(async (req, res) => {
  const { role, id } = req.body

  const user = await User.findById(id)
  if (!user) {
    res.status(400)
    throw new Error('User not found')
  }

  user.role = role
  await user.save()

  res.status(200).json({
    message: `User role updated to ${role}`,
  })
})

// send automated emails ///////////////
const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body

  if (!subject || !send_to || !reply_to || !template) {
    res.status(500)
    throw new Error('Missing email paramater')
  }

  // get user
  const user = await User.findOne({ email: send_to })
  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  const sent_from = process.env.EMAIL_USER
  const name = user.name
  const link = `${process.env.FRONTEND_URL}${url}`

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({ message: 'Email sent' })
  } catch (error) {
    res.status(500)
    throw new Error('Email not sent, Please try again')
  }
})

// send verification email /////////////////
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id)

  // check if user exists
  if (!user) {
    res.status(400)
    throw new Error('User not found, Please sign up')
  }
  if (user.isVerified) {
    res.status(400)
    throw new Error('User is already verified')
  }

  // delete token if it exist in db
  const token = await Token.findOne({ userId: user._id })

  if (token) {
    await token.deleteOne()
  }

  // create a verification token and save
  const verificationToken = crypto.randomBytes(32).toString('hex') + user._id
  console.log(verificationToken)

  // hash token and save
  const hashedToken = hashToken(verificationToken)
  await new Token({
    userId: user._id,
    verifyToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save()

  // construct verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`

  // send email
  const subject = 'Verify Your Account'
  const send_to = user.email
  const sent_from = process.env.EMAIL_USER
  const reply_to = 'noreply@mrreact.com'
  const template = 'verifyEmail'
  const name = user.name
  const link = verificationUrl

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({ message: 'Verification email sent' })
  } catch (error) {
    res.status(500)
    throw new Error('Email not sent, Please try again')
  }
})

// Verify User /////////////////////////////
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params

  const hashedToken = hashToken(verificationToken)

  const userToken = await Token.findOne({
    verifyToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or expired token')
  }

  // find user
  const user = await User.findOne({ _id: userToken.userId })

  if (user.isVerified) {
    res.status(400)
    throw new Error('User is already verified')
  }

  // verify user
  user.isVerified = true
  await user.save()

  res.status(200).json({
    message: 'Account verification successful',
  })
})

// forgot password //////////////////////////
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body

  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error('No user with this email')
  }

  // delete token if it exists in db
  const token = await Token.findOne({ userId: user._id })

  if (token) {
    await token.deleteOne()
  }

  // create a verification token and save
  const resetToken = crypto.randomBytes(32).toString('hex') + user._id
  console.log(resetToken)

  // hash token and save
  const hashedToken = hashToken(resetToken)
  await new Token({
    userId: user._id,
    resetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save()

  // construct reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`

  // send email
  const subject = 'Password reset request - MrReact '
  const send_to = user.email
  const sent_from = process.env.EMAIL_USER
  const reply_to = 'noreply@mrreact.com'
  const template = 'forgotPassword'
  const name = user.name
  const link = resetUrl

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({ message: 'Password reset email sent' })
  } catch (error) {
    res.status(500)
    throw new Error('Email not sent, Please try again')
  }
})

// reset password /////////////////////////////
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params
  const { password } = req.body
  // console.log(resetToken)
  // console.log(password)

  const hashedToken = hashToken(resetToken)

  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or expired token')
  }

  // find user
  const user = await User.findOne({ _id: userToken.userId })

  // reset password
  user.password = password
  await user.save()

  res.status(200).json({
    message: 'Password reset successful, Please log in',
  })
})

// Change Password /////////////////////////////
const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, password } = req.body
  const user = await User.findById(req.user._id)

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  if (!oldPassword || !password) {
    res.status(400)
    throw new Error('Please enter old and new password')
  }

  // Check if old password is correct
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

  // Save new password
  if (user && passwordIsCorrect) {
    user.password = password
    await user.save()

    res
      .status(200)
      .json({ message: 'Password changed successfully, please login' })
  } else {
    res.status(400)
    throw new Error('Old password is incorrect')
  }
})

// Send Login Code ///////////////////////////
const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params
  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  // Find Login Code in DB
  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or Expired token')
  }

  const loginCodes = userToken.loginToken
  const decryptedLoginCode = cryptr.decrypt(loginCodes)

  console.log(decryptedLoginCode)
  // // Send Login Code
  const subject = 'Login Access Code '
  const send_to = email
  const sent_from = process.env.EMAIL_USER
  const reply_to = 'noreply@mrreact.com'
  const template = 'loginCode'
  const name = user.name
  const link = decryptedLoginCode

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link)
    res.status(200).json({ message: `Access code sent to ${email}` })
  } catch (error) {
    res.status(500)
    throw new Error('Email not sent, please try again')
  }
})

// Login With Code ////////////////////////////
const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params
  const { loginCode } = req.body

  const user = await User.findOne({ email })

  if (!user) {
    res.status(404)
    throw new Error('User not found')
  }

  // Find user Login Token
  const userToken = await Token.findOne({
    userId: user.id,
    expiresAt: { $gt: Date.now() },
  })

  if (!userToken) {
    res.status(404)
    throw new Error('Invalid or Expired Token, please try again')
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken)

  if (loginCode !== decryptedLoginCode) {
    res.status(400)
    throw new Error('Incorrect login code, please try again')
  } else {
    // Register userAgent
    const ua = parser(req.headers['user-agent'])
    const thisUserAgent = ua.ua
    user.userAgent.push(thisUserAgent)
    await user.save()

    // Generate Token
    const token = generateToken(user._id)

    // Send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true,
    })

    const { _id, name, email, phone, bio, photo, role, isVerified } = user

    res.status(200).json({
      _id,
      name,
      email,
      phone,
      bio,
      photo,
      role,
      isVerified,
      token,
    })
  }
})

// login with google /////////////////////////
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body
  // console.log(userToken);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  })

  const payload = ticket.getPayload()

  const { name, email, sub, picture } = payload
  const password = Date.now() + sub

  // get user agent
  const ua = parser(req.headers['user-agent'])
  const userAgent = [ua.ua]

  // check if user exist
  const user = await User.findOne({ email })

  if (!user) {
    // create user
    const newUser = await User.create({
      name,
      email,
      password,
      photo: picture,
      isVerified: true,
      userAgent,
    })

    if (newUser) {
      // Generate Token
      const token = generateToken(newUser._id)

      // send HTTP-only cookie
      res.cookie('token', token, {
        path: '/',
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: 'none',
        secure: true,
      })

      if (newUser) {
        const { _id, name, email, phone, photo, bio, role, isVerified } =
          newUser

        res.status(201).json({
          _id,
          name,
          email,
          phone,
          photo,
          bio,
          role,
          isVerified,
          token,
        })
      }
    }
  }

  // if user exist, login
  if (user) {
    // Generate Token
    const token = generateToken(user._id)

    // send HTTP-only cookie
    res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: 'none',
      secure: true,
    })

    if (user) {
      const { _id, name, email, phone, photo, bio, role, isVerified } = user

      res.status(201).json({
        _id,
        name,
        email,
        phone,
        photo,
        bio,
        role,
        isVerified,
        token,
      })
    }
  }
})

//exports
module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
}
