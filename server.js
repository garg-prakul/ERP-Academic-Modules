import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pg from "pg";
import bodyParser from "body-parser";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();
const app = express();
const port = process.env.SERVER_PORT || 3000;
let verificationCodes = {}; // Store codes temporarily

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Database connection
const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

db.connect()
    .then(() => console.log("Connected to database"))
    .catch((err) => console.error("Database connection error:", err));

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Determine user role based on email
function getUserRole(email) {
    if (email.endsWith("@student.iitmandi.ac.in")) return "student";
    if (email.endsWith("@admin.iitmandi.ac.in")) return "admin";
    if (email.endsWith("@faculty.iitmandi.ac.in")) return "faculty";
    return "unknown";
}

// Home page
app.get("/", (req, res) => {
    res.render("home.ejs");
});

// Login page
app.get("/login", (req, res) => {
    res.render("login.ejs");
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await db.query("SELECT password FROM users WHERE email = $1", [email]);

        if (result.rows.length > 0) {
            const hashedPassword = result.rows[0].password;
            const match = await bcrypt.compare(password, hashedPassword);

            if (match) {
                const role = getUserRole(email);
                if (role === "student") return res.render("student.ejs");
                if (role === "faculty") return res.render("faculty.ejs");
                if (role === "admin") return res.render("acadOffice.ejs");

                return res.send("Login successful!");
            } else {
                res.status(401).redirect("/login");
            }
        } else {
            res.status(404).render("login.ejs", { error: "User not found. Please sign up." });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
    }
});

// ✅ Step 1: Request Forgot Password (Send Verification Code)
app.get("/forget-password", (req, res) => {
    res.render("forget-password.ejs");
});

app.post("/forget-password", async (req, res) => {
    const { email } = req.body;

    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            return res.status(404).send("User not found");
        }

        // Generate a 6-digit random code
        const randomCode = crypto.randomInt(100000, 999999).toString();
        verificationCodes[email] = randomCode;

        // Send email with verification code
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Password Reset Verification Code",
            text: `Your verification code is: ${randomCode}. It is valid for 10 minutes.`,
        };

        await transporter.sendMail(mailOptions);
        console.log(`Verification code sent: ${randomCode}`);

        res.render("verify.ejs", { email }); // Redirect to verify page
    } catch (error) {
        console.error(error);
        res.status(500).send("Error sending verification code.");
    }
});


app.post("/verify", (req, res) => {
    const { email, code } = req.body;

    if (verificationCodes[email] && verificationCodes[email] === code) {
        delete verificationCodes[email]; // Remove used code
        const role = getUserRole(email);

        if (role === "student") return res.render("student.ejs");
        if (role === "faculty") return res.render("faculty.ejs");
        if (role === "admin") return res.render("acadOffice.ejs");

        return res.redirect("/login");
    } else {
        res.send("Invalid verification code. Please try again.");
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
