const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../routes/models/User')
const router = Router()

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Not valid e-mail').isEmail(),
        check('password', 'Password must contain minimum 6 symbols')
        .isLength({ min:6 })
    ],
    async (req, res) => {
    try{

        const errors = validationResult(req)

        if (!errors.isEmpty) {
            return res.status(400).json({
                errors: errors.array(),
                message: 'Not valid registration data, please check your data and try again'
            })
        }
        const {email, password} = req.body

        const candidate = await User.findOne( {email} )

        if (candidate){
            return res.status(400).json({ message: 'There is already such user'}) 
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword})

        await user.save()

        res.status(201).json({message: 'User has been created'})
    } catch (e){
        res.status(500).json({ message: 'Something is not alright, try again'})
    }
})

// /api/auth/login
router.post(
    '/login',
    [
        check('email', 'Enter valid email').normalizeEmail().isEmail(),
        check('password', 'Enter your password').exists()
    ],
    async (req, res) => {
            try{
                const errors = validationResult(req)
        
                if (!errors.isEmpty) {
                    return res.status(400).json({
                        errors: errors.array(),
                        message: 'Not valid login data, please check your data and try again'
                    })
                }

                const {email, password} = req.body

                const user = await User.findOne({ email })

                if (!user){
                    return res.status(400).json({ message: 'User not found'})
                }

                const isMatch = await bcrypt.compare(password, user.password)

                if (!isMatch){
                    return res.status(400).json({ message: 'Incorrect password, try again'} )
                }

                const token = jwt.sign(
                    { userId: user.id },
                    config.get('jwtSecret'),
                    { expiresIn: '1h' }
                )

                res.json({ token, userId: user.id})

            } catch (e){
                res.status(500).json({ message: 'Something is not alright, try again'})
            }
})

module.exports = router