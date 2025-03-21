const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected')).catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false }
});

const User = mongoose.model('User', UserSchema);

// Nodemailer Config
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS
    }
});

// Signup Route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email.endsWith('@yourinstitute.edu')) {
        return res.status(400).json({ message: 'Only institute emails allowed' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();
    
    // Send verification email
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const verificationLink = `http://localhost:5000/verify/${token}`;
    
    await transporter.sendMail({
        to: email,
        subject: 'Verify Your Email',
        html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`
    });
    
    res.json({ message: 'Verification email sent. Please check your inbox.' });
});

// Email Verification Route
app.get('/verify/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await User.findOneAndUpdate({ email: decoded.email }, { isVerified: true });
        res.json({ message: 'Email verified successfully. You can now log in.' });
    } catch (error) {
        res.status(400).json({ message: 'Invalid or expired token' });
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (!user.isVerified) return res.status(400).json({ message: 'Email not verified' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Incorrect password' });
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
});

// Start Server
app.listen(5000, () => console.log('Server running on port 5000'));
