const express = require('express')
const mongoose = require('mongoose')
const dotenv = require('dotenv').config()
const cors = require('cors')
const colors = require('colors')
const cookieParser = require('cookie-parser')
const bodyParser = require('body-parser')
const userRoute = require('./routes/userRoutes')
const errorHandler = require('./middleware/errorMiddleware')

const app = express()

// middlwares
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(
  cors({
    origin: [
      'http://localhost:3000',
      'https://adv-auth-ahmdreshad.vercel.app',
      'https://adv-auth.vercel.app',
    ],
    credentials: true,
  })
)

// Routes
app.use('/api/users', userRoute)

app.get('/', (req, res) => {
  res.send('Home Page')
})

// Error middleware
app.use(errorHandler)
const PORT = process.env.PORT || 5000
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`DB connected to ${mongoose.connection.name}`.cyan.underline)
      console.log(`Server is running at port:${PORT}`.yellow.bold)
    })
  })
  .catch((err) => console.log(err).red.underline.bold)
