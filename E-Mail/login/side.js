const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

app.use(express.json());

// Login endpoint
app.post('login/login.html', async (req, res) => {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Query the database to find the user
    const user = await db.query(`SELECT * FROM users WHERE email = ?`, email);

    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Compare the provided password with the hashed password in the database
    const isValidPassword = await bcrypt.compare(password, user.hashed_password);

    if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // If credentials match, redirect to the User Home page
    res.redirect('Home/User.html');
});

// Create account endpoint
app.post('createAcc/create.html', async (req, res) => {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required.' });
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database
    await db.query(`INSERT INTO users (email, hashed_password) VALUES (?, ?)`, email, hashedPassword);

    // Redirect to the login page
    res.redirect('login/login.html');
});

app.listen(3000, () => {
    console.log('Server listening on port 3000');
});