import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pg from "pg";
import bodyParser from "body-parser";
import nodemailer from "nodemailer";
import crypto from "crypto";

dotenv.config();
const app = express();
const port = process.env.SERVER_PORT || 4000; // Ensure SERVER_PORT is defined in .env
let verificationCodes = {}; // Store codes temporarily

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // Updated path to serve static files
app.set("view engine", "ejs"); // Ensure EJS is set as the view engine

// Database connection
const db = new pg.Client({
    user: process.env.DB_USER , // Ensure DB_USER is defined in .env
    host: process.env.DB_HOST , // Ensure DB_HOST is defined in .env
    database: process.env.DB_NAME , // Ensure DB_NAME is defined in .env
    password: process.env.DB_PASSWORD , // Ensure DB_PASSWORD is defined in .env
    port: process.env.DB_PORT , // Ensure DB_PORT is defined in .env
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
    if (email.endsWith("@students.iitmandi.ac.in")) return "student";
    if (email.endsWith("@admin.iitmandi.ac.in")) return "admin";
    if (email.endsWith("@faculty.iitmandi.ac.in")) return "faculty";
    return "unknown";
}

// Home page
app.get("/", (req, res) => {
    res.render("../views/home.ejs");
});

// Login page
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Determine the role based on the email
        const role = getUserRole(email);

        if (role === "student") {
            const result = await db.query("SELECT * FROM student WHERE email = $1", [email]);

            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);

                if (match) {
                    const name = result.rows[0].name;
                    const currDate = new Date().toLocaleDateString(); // Get current date

                    const studentId = result.rows[0].student_id;
                    try {
                        // Fetch semester-wise courses and grades
                        const courseTable = await db.query(`
                            SELECT 
                                s.semester_number, 
                                s.year, 
                                c.name AS course_name, 
                                e.grade, 
                                c.credits
                            FROM enrollment e
                            JOIN course c ON e.course_id = c.course_id
                            JOIN semester s ON e.semester_id = s.semester_id
                            WHERE e.student_id = $1
                            ORDER BY s.year ASC, s.semester_number ASC;
                        `, [studentId]);

                        // Organize courses by semester
                        const coursesBySemester = {};
                        let totalCredits = 0;

                        courseTable.rows.forEach(row => {
                            const semester = `Semester ${row.semester_number} (${row.year})`;
                            if (!coursesBySemester[semester]) {
                                coursesBySemester[semester] = [];
                            }

                            coursesBySemester[semester].push({
                                course: row.course_name,
                                grade: row.grade,
                                credits: row.credits
                            });

                            // Assuming passing grade is not 'F'
                            if (row.grade !== 'F') {
                                totalCredits += row.credits;
                            }
                        });

                        return res.render("student.ejs", { name: name, currDate: currDate, coursesBySemester: coursesBySemester, totalCredits: totalCredits });

                    } catch (err) {
                        console.error("Error fetching courses:", err);
                        return res.status(500).render("login.ejs", { error: "Error fetching courses. Please try again later." });
                    }

                } else {
                    return res.status(401).render("login.ejs", { error: "Invalid password. Please try again." });
                }
            } else {
                return res.status(404).render("login.ejs", { error: "User not found. Please sign up." });
            }
        } else if (role === "faculty") {
            // Handle faculty login
            const result = await db.query("SELECT * FROM faculty WHERE email = $1", [email]);

            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);

                if (match) {
                    const name = result.rows[0].name;
                    return res.render("faculty.ejs", { name: name });
                } else {
                    return res.status(401).render("login.ejs", { error: "Invalid password. Please try again." });
                }
            } else {
                return res.status(404).render("login.ejs", { error: "User not found. Please sign up." });
            }
        } else if (role === "admin") {
            // Handle admin login
            const result = await db.query("SELECT * FROM admin WHERE email = $1", [email]);

            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);

                if (match) {
                    const name = result.rows[0].name;
                    return res.render("acadOffice.ejs", { name: name });
                } else {
                    return res.status(401).render("login.ejs", { error: "Invalid password. Please try again." });
                }
            } else {
                return res.status(404).render("login.ejs", { error: "User not found. Please sign up." });
            }
        } else {
            return res.status(400).render("login.ejs", { error: "Invalid email domain. Please use your IIT Mandi email." });
        }
    } catch (error) {
        console.error("Error logging in:", error);
        return res.status(500).render("login.ejs", { error: "An unexpected error occurred. Please try again later." });
    }
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/register", async (req, res) => {
    const { email, password, confirmPassword, name, department, student_id } = req.body;

    try {
        // Determine the role based on the email
        const role = getUserRole(email);

        if (role === "student") {
            // Check if the email is already registered in the student table
            const existingUser = await db.query("SELECT * FROM student WHERE email = $1", [email]);
            if (existingUser.rows.length > 0) {
                console.log("Email is already registered:", email);
                return res.status(400).render("register.ejs", { error: "Email is already registered. Please log in." });
            }

            // Check if password and confirm password match
            if (password !== confirmPassword) {
                console.log("Passwords do not match:", password, confirmPassword);
                return res.status(400).render("register.ejs", { error: "Passwords do not match. Please try again." });
            }

            // Hash the password and insert the student into the database
            const hashedPassword = await bcrypt.hash(password, 10);
            const query = `
                INSERT INTO student (name, email, student_id, department, password)
                VALUES ($1, $2, $3, $4, $5) RETURNING *`;
            const values = [name, email, student_id, department, hashedPassword];

            try {
                const result = await db.query(query, values);
                console.log("Student registered:", result.rows[0]);

                // Render the student page with the student's name and current date
                const currDate = new Date().toLocaleDateString(); // Get current date
                return res.render("student.ejs", { name: name, currDate: currDate });
            } catch (dbError) {
                console.error("Database query error:", dbError);
                return res.status(500).render("register.ejs", { error: "Database error. Please try again later." });
            }
        } else if (role === "faculty") {
            // Handle faculty registration (if applicable)
            // ...existing code...
        } else if (role === "admin") {
            // Handle admin registration (if applicable)
            // ...existing code...
        } else {
            console.log("Invalid email domain:", email);
            return res.status(400).render("register.ejs", { error: "Invalid email domain. Please use your IIT Mandi email." });
        }
    } catch (error) {
        console.error("Error registering user:", error);
        res.status(500).render("register.ejs", { error: "An unexpected error occurred. Please try again later." });
    }
});

app.get("/forget-password", (req, res) => {
    res.render("../views/forget-password.ejs");
});

app.post("/forget-password", async (req, res) => {
    const { email } = req.body;

    try {
        const result = await db.query("SELECT * FROM user_data WHERE email = $1", [email]);

        if (result.rows.length === 0) {
            console.log("User not found:", email);
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

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res.status(500).send(`Error sending verification code: ${error.message}`);
            } else {
                console.log(`Verification code sent to ${email}: ${randomCode}`);
                res.render("verify.ejs", { email }); // Redirect to verify page
            }
        });
    } catch (error) {
        console.error("Error sending verification code:", error);
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

