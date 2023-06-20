const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please enter your name'],
    },
    email: {
      type: String,
      required: [true, 'Please Enter your email'],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please enter a valid email',
      ],
    },
    password: {
      type: String,
      required: [true, 'Please enter your password'],
    },
    photo: {
      type: String,
      required: [true, 'Please add your photo'],
      default: 'https://ibb.co/YQSvY2R',
    },
    phone: {
      type: String,
      default: '+91-123-456-7890',
    },
    bio: {
      type: String,
      default: 'Bio',
    },
    role: {
      type: String,
      required: true,
      default: 'subscriber',
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    userAgent: {
      type: Array,
      required: true,
      default: [],
    },
  },
  {
    timestamps: true,
    minimize: false,
  }
)


// incrypting the password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next()
  }

  // hash the password
  const salt = await bcrypt.genSalt(12)
  const hashedPassword = await bcrypt.hash(this.password, salt)
  this.password = hashedPassword
  next()
})

const User = mongoose.model('User', userSchema)
module.exports = User
