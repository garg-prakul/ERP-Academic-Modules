import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pg from "pg";
import bodyParser from "body-parser";
import nodemailer from "nodemailer";
import crypto from "crypto";
import methodOverride from 'method-override';
import session from 'express-session';
import pgSession from 'connect-pg-simple';

dotenv.config();
const app = express();
const port = process.env.SERVER_PORT || 4000; // Ensure SERVER_PORT is defined in .env
let verificationCodes = {}; // Store codes temporarily

app.use(methodOverride('_method'));
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
// not working currently
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Add before other middleware
app.use(session({
    store: new (pgSession(session))({
        pool: db,
        tableName: 'user_sessions'
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

// Determine user role based on email
function getUserRole(email) {
    if (!email) return "unknown";
    email = email.toString().toLowerCase();
    if (email.endsWith("@students.iitmandi.ac.in")) return "student";
    if (email.endsWith("@admin.iitmandi.ac.in")) return "admin";
    if (email.endsWith("@faculty.iitmandi.ac.in")) return "faculty";
    return "unknown";
}

// Add auth middleware
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.redirect('/login');
    }
    next();
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
           // Change this query in the login route
            const result = await db.query("SELECT * FROM students WHERE email = $1", [email]);

            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);

                if (match) {
                    const name = result.rows[0].student_name;  // Changed from name
                    const currDate = new Date().toLocaleDateString();
                    const rollNo = result.rows[0].roll_no;     // Changed from student_id

                    try {
                        // Updated query with new table and column names
                        const courseTable = await db.query(`
                            SELECT 
                                s.semester_number, 
                                s.year,     
                                c.course_code,
                                c.instructor_name, 
                                e.grade, 
                                c.credit
                            FROM enrollment e
                            JOIN courses c ON e.course_code = c.course_code
                            JOIN semester s ON e.semester_id = s.semester_id
                            WHERE e.roll_no = $1
                            ORDER BY s.year ASC, s.semester_number ASC;
                        `, [rollNo]);

                        // Organize courses by semester
                        const coursesBySemester = {};
                        let totalCredits = 0;

                        courseTable.rows.forEach(row => {
                            const semester = `Semester ${row.semester_number} (${row.year})`;
                            if (!coursesBySemester[semester]) {
                                coursesBySemester[semester] = [];
                            }

                            coursesBySemester[semester].push({
                                course: row.course_code,
                                grade: row.grade,
                                credits: row.credit
                            });

                            // Assuming passing grade is not 'F'
                            if (row.grade !== 'F') {
                                totalCredits += row.credit;
                            }
                        });

                        // Set session data on successful login
                        req.session.user = {
                            ...result.rows[0],
                            role: role // student/faculty/admin
                        };

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
            const query = email.startsWith('F') 
                ? "SELECT * FROM instructors WHERE instructor_id = $1"
                : "SELECT * FROM instructors WHERE email = $1";
            
            console.log('Faculty login attempt for:', email); // Debug log
            const result = await db.query(query, [email]);
            console.log('Query result:', result.rows); // Debug log
        
            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);
        
                if (match) {
                    // Set session data
                    req.session.user = {
                        ...result.rows[0],
                        role: 'instructor'
                    };
                    console.log('Faculty session:', req.session.user); // Debug log
                    
                    // Redirect to instructor dashboard instead of rendering
                    return res.redirect('/instructor-dashboard');
                } else {
                    return res.status(401).render("login", { error: "Invalid password" });
                }
            } else {
                return res.status(404).render("login", { error: "Faculty not found. Please register first." });
            }
        } else if (role === "admin") {
            // Handle admin login
            const result = await db.query("SELECT * FROM admin WHERE email = $1", [email]);

            if (result.rows.length > 0) {
                const hashedPassword = result.rows[0].password;
                const match = await bcrypt.compare(password, hashedPassword);

                if (match) {
                    const name = result.rows[0].name;

                    // Set session data on successful login
                    req.session.user = {
                        ...result.rows[0],
                        role: role // student/faculty/admin
                    };

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

// Add logout route
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});
app.get("/admin-register", (req, res) => {
    res.render("admin-register.ejs");
});
app.get("/faculty-register", (req, res) => {
    res.render("faculty-register.ejs");
});

app.get("/enrollment", (req, res) => {
    res.render("enrollment.ejs");
});

app.post("/enrollment", async (req, res) => {
    const { year, sem_type } = req.body;
  
    if (!year || !sem_type) {
        return res.status(400).json({ error: "Year and semester type are required" });
    }

    const semNumbers = sem_type === 'odd' ? [1, 3, 5, 7] : [2, 4, 6, 8];
  
    try {
        await db.query('BEGIN');

        // First insert enrollments
        const insertQuery = `
            INSERT INTO enrollment (roll_no, course_code, semester_id, grade)
            SELECT DISTINCT
                cr.roll_no,
                cr.course_code,
                s.semester_id,
                'NA' as grade
            FROM
                course_registration cr
            INNER JOIN
                semester s ON cr.roll_no = s.roll_no
            WHERE
                s.year = $1
                AND s.semester_number = ANY($2::int[])
                AND NOT EXISTS (
                    SELECT 1 
                    FROM enrollment e
                    WHERE e.roll_no = cr.roll_no
                        AND e.course_code = cr.course_code
                        AND e.semester_id = s.semester_id
                )
            RETURNING *;
        `;
  
        const result = await db.query(insertQuery, [year, semNumbers]);

        // Reset all students' submission counts and clear registration tables
        await db.query(`
            UPDATE students 
            SET submission_count = 0,
                registration_count = 0 
            WHERE roll_no IN (
                SELECT DISTINCT roll_no 
                FROM course_registration
            )`
        );

        // Clear registration tables
        await db.query("DELETE FROM course_registration");
        await db.query("DELETE FROM course_pre_registration");

        await db.query('COMMIT');

        res.status(201).json({
            success: true,
            message: "Enrollment completed and registration tables reset",
            count: result.rowCount,
            enrollments: result.rows
        });

    } catch (err) {
        await db.query('ROLLBACK');
        console.error("Error in enrollment process:", err);
        res.status(500).json({ 
            error: "Internal server error", 
            details: err.message
        });
    }
});

app.post("/register", async (req, res) => {
    try {
        const { email, password, confirmPassword, name, student_branch_code, roll_no } = req.body;

        // Basic validation
        if (!email || !password || !name || !student_branch_code || !roll_no) {
            return res.render("register.ejs", { error: "All fields are required" });
        }

        if (password !== confirmPassword) {
            return res.render("register.ejs", { error: "Passwords do not match" });
        }

        // Email domain validation
        if (!email.endsWith("@students.iitmandi.ac.in")) {
            return res.render("register.ejs", { error: "Please use your IIT Mandi student email" });
        }

        // Check if student already exists
        const checkUser = await db.query("SELECT * FROM students WHERE email = $1 OR roll_no = $2", [email, roll_no]);
        if (checkUser.rows.length > 0) {
            return res.render("register.ejs", { error: "Student with this email or roll number already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert student
        const insertQuery = `
            INSERT INTO students (student_name, email, roll_no, student_branch_code, password)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *`;
        
        const result = await db.query(insertQuery, [name, email, roll_no, student_branch_code, hashedPassword]);
        
        // Redirect to student dashboard
        res.render("student.ejs", {
            name: result.rows[0].student_name,
            currDate: new Date().toLocaleDateString(),
            coursesBySemester: {},
            totalCredits: 0
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.render("register.ejs", { error: "Registration failed. Please try again." });
    }
});

app.post('/admin-register', async (req, res) => {
    const { admin_name, admin_id, email, password } = req.body;
  
    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert into admin table
      await db.query(
        'INSERT INTO admin (admin_id, admin_name, email, password) VALUES ($1, $2, $3, $4)',
        [admin_id, admin_name, email, hashedPassword]
      );
  
      res.send('Admin registered successfully!');
    } catch (err) {
      console.error(err);
      res.status(500).send('Error registering admin.');
    }
  });
  
  // Instructor Registration Route (POST)
  app.post('/faculty-register', async (req, res) => {
    const { instructor_name, instructor_id, course_code, email, password } = req.body;
  
    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert into instructors table
      await db.query(
        'INSERT INTO instructors (instructor_id, instructor_name, course_code, email, password) VALUES ($1, $2, $3, $4, $5)',
        [instructor_id, instructor_name, course_code, email, hashedPassword]
      );
  
      res.send('Instructor registered successfully!');
    } catch (err) {
      console.error(err);
      res.status(500).send('Error registering instructor.');
    }
  });


//   semester routes

  app.get("/add-semester", (req, res) => {
    res.render("add-semester.ejs");
  });

  app.post('/add-semester', async (req, res) => {
    const { roll_no, semester_number, year } = req.body;
  
    try {
      await db.query(
        `INSERT INTO semester (roll_no, semester_number, year)
         VALUES ($1, $2, $3)`,
        [ roll_no, semester_number, year]
      );
      res.send('Semester added successfully!');
    } catch (err) {
      console.error(err);
      res.status(500).send('Error adding semester.');
    }
  });

  
 // not working currently 

app.get("/forget-password", (req, res) => {
    res.render("../views/forget-password.ejs");
});

// not working currently
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


// not working currently
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






// Get all courses
app.get("/all-courses", requireAuth, async (req, res) => {
    try {
        const allCourses = await db.query("SELECT * FROM courses");
        res.render("AllCourses", { 
            courses: allCourses.rows,
            search: req.query.search || ''
        });
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});

app.get("/course-list", requireAuth, async (req, res) => {
    try {
        const allCourses = await db.query("SELECT * FROM courses");
        res.render("CourseList", { 
            courses: allCourses.rows,
            search: req.query.search || ''
        });
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});

// Add new course
app.get("/add-course", requireAuth, async (req, res) => {
    try {
        // Define branch options for DC/DE
        const deforOptions = ['CSE','DSE','EP', 'VLSI', 'EE', 'ME', 'CE','GE','MNC'];
        res.render("AddCourse", { deforOptions });
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});

app.post("/add-course", requireAuth, async (req, res) => {
    try {
        const {
            course_code,
            course_name,
            instructor_name,
            instructor_id,
            avail,
            dcfor,
            defor,
            icornot,
            slot,
            credit,
            ltpc
        } = req.body;

        // Convert checkboxes to arrays
        const dcforArray = Array.isArray(dcfor) ? dcfor : [dcfor];
        const deforArray = Array.isArray(defor) ? defor : [defor];
        console.log("hello");
        const newCourse = await db.query(
            `INSERT INTO courses (course_code, course_name, instructor_name, instructor_id, avail, dcfor, defor, icornot, slot, credit, ltpc)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
            [course_code, course_name, instructor_name, instructor_id, avail, dcforArray, deforArray, icornot, slot, credit, ltpc]
        );
        
        res.redirect("/all-courses");
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});

// Edit course
app.get("/edit-course/:course_code", requireAuth, async (req, res) => {
    try {
        const { course_code } = req.params;
        const course = await db.query("SELECT * FROM courses WHERE course_code = $1", [course_code]);
        
        if (course.rows.length === 0) {
            return res.render("error", { message: "Course not found" });
        }
        
        // Define branch options for DC/DE
        const deforOptions = ['CSE','DSE','EP', 'VLSI', 'EE', 'ME', 'CE','GE','MNC'];
        
        res.render("EditCourse", { 
            course: course.rows[0],
            deforOptions: deforOptions
        });
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});

app.put("/edit-course/:course_code", requireAuth, async (req, res) => {
    try {
        const { course_code } = req.params;
        const {
            course_name,
            instructor_name,
            instructor_id,
            avail,
            dcfor,
            defor,
            icornot,
            slot,
            credit,
            ltpc
        } = req.body;

        // Convert checkboxes to arrays
        const dcforArray = Array.isArray(dcfor) ? dcfor : [dcfor];
        const deforArray = Array.isArray(defor) ? defor : [defor];
        
        const updateResult = await db.query(
            `UPDATE courses 
            SET course_name = $1, instructor_name = $2, instructor_id = $3, 
            avail = $4, dcfor = $5, defor = $6, icornot = $7, 
            slot = $8, credit = $9, ltpc = $10
            WHERE course_code = $11 RETURNING *`,
            [course_name, instructor_name, instructor_id, avail, dcforArray, deforArray, 
                icornot, slot, credit, ltpc, course_code]
            );
            
        if (updateResult.rowCount === 0) {
            return res.render("error", { message: "Course not found" });
        }

        res.redirect("/all-courses");
    } catch (error) {
        console.error(error.message);
        res.render("error", { message: error.message });
    }
});


// Delete course
app.delete("/courses/:course_code", requireAuth, async (req, res) => {
    try {
        const { course_code } = req.params;
        
        // First check if course exists in enrollments
        const enrollmentCheck = await db.query(
            "SELECT COUNT(*) FROM enrollment WHERE course_code = $1",
            [course_code]
        );
        
        if (enrollmentCheck.rows[0].count > 0) {
            return res.render("error", { 
                message: "Cannot delete course - it has existing enrollments. Archive it instead." 
            });
        }
        
        // If no enrollments, proceed with deletion
        const deleteResult = await db.query(
            "DELETE FROM courses WHERE course_code = $1 RETURNING *",
            [course_code]
        );
        
        if (deleteResult.rowCount === 0) {
            return res.render("error", { message: "Course not found" });
        }
        
        res.redirect("/all-courses");
    } catch (error) {
        console.error(error.message);
        res.render("error", { 
            message: "Cannot delete course. It may be referenced by other records." 
        });
    }
});


// 1. Course Pre-Registration (Max 3 submissions)
// Pre-Registration Route
app.get('/course-pre-registration', requireAuth, async (req, res) => {
    try {
        const student = req.session.user;
        
        // Check if student exists and get current submission count
        const studentResult = await db.query(
            'SELECT submission_count FROM students WHERE roll_no = $1',
            [student.roll_no]
        );
        
        // Changed from 100 to 10
        if (studentResult.rows[0].submission_count >= 10) {
            return res.render('error', { 
                message: 'Maximum pre-registration attempts (10) reached' 
            });
        }

        // Get eligible courses - Fixed array comparison
        const courses = await db.query(`
            SELECT c.*, 
                   COALESCE(
                       (SELECT status 
                        FROM course_pre_registration 
                        WHERE roll_no = $1 
                        AND course_code = c.course_code
                       ), 'none'
                   ) as registration_status
            FROM courses c
            WHERE c.avail = 'yes' 
            AND ($2 = ANY(c.dcfor) 
                 OR $2 = ANY(c.defor) 
                 OR c.icornot = 'IC')
            ORDER BY c.slot
        `, [student.roll_no, student.student_branch_code]);

        const coursesBySlot = courses.rows.reduce((acc, course) => {
            acc[course.slot] = acc[course.slot] || [];
            acc[course.slot].push(course);
            return acc;
        }, {});

        res.render('CoursePreRegistration', {
            coursesBySlot,
            student,
            submissionCount: studentResult.rows[0].submission_count
        });
    } catch (err) {
        res.status(500).render('error', { message: err.message });
    }
});

app.post('/submit-pre-registration', requireAuth, async (req, res) => {
    try {
        await db.query('BEGIN');
        const student = req.session.user;
        
        console.log('Request body:', req.body); // Debug log

        const { selectedCourses } = req.body;
        
        if (!selectedCourses || !Array.isArray(selectedCourses)) {
            throw new Error('No courses selected');
        }

        console.log('Selected courses:', selectedCourses); // Debug log

        // First, check if student has already submitted 3 times
        const studentCheck = await db.query(
            'SELECT submission_count FROM students WHERE roll_no = $1',
            [student.roll_no]
        );

        // Changed from 100 to 10
        if (studentCheck.rows[0].submission_count >= 10) {
            throw new Error('Maximum 10 submissions reached');
        }

        // Insert pre-registrations one by one to avoid array issues
        for (const courseCode of selectedCourses) {
            await db.query(`
                INSERT INTO course_pre_registration 
                (roll_no, course_code, status) 
                VALUES ($1, $2, 'pending')
                ON CONFLICT (roll_no, course_code) 
                DO UPDATE SET status = 'pending'
            `, [student.roll_no, courseCode]);
        }

        // Update submission count
        await db.query(`
            UPDATE students 
            SET submission_count = submission_count + 1 
            WHERE roll_no = $1
        `, [student.roll_no]);

        await db.query('COMMIT');
        res.redirect('/pre-registered-courses');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Pre-registration error:', err); // Debug log
        res.status(500).render('error', { 
            message: `Pre-registration failed: ${err.message}` 
        });
    }
});

// 2. Pre-Registered Courses (Accepted)
app.get('/pre-registered-courses', requireAuth, async (req, res) => {
    try {
        if (!req.session.user || !req.session.user.roll_no) {
            return res.redirect('/login');
        }

        const { roll_no } = req.session.user;
        console.log("Fetching pre-registered courses for:", roll_no); // Debug log

        const result = await db.query(`
            SELECT pr.*, c.*
            FROM course_pre_registration pr
            JOIN courses c ON pr.course_code = c.course_code
            WHERE pr.roll_no = $1
        `, [roll_no]);

        console.log("Query result:", result.rows); // Debug log

        res.render('PreRegisteredCourses', { 
            courses: result.rows,
            student: req.session.user
        });
    } catch (err) {
        console.error('Error in pre-registered courses:', err);
        res.status(500).render('error', { 
            message: 'Error loading pre-registered courses: ' + err.message 
        });
    }
});

// 3. Course Registration (Only 1 submission)
app.get('/course-registration', requireAuth, async (req, res) => {
    try {
        const { roll_no } = req.session.user;
        
        // Check registration attempt count
        const registrationCheck = await db.query(
            'SELECT registration_count FROM students WHERE roll_no = $1',
            [roll_no]
        );

        if (registrationCheck.rows[0].registration_count >= 1) {
            return res.render('error', { 
                message: 'You have already used your registration attempt for this semester.' 
            });
        }

        // First check if student has any accepted pre-registrations
        const acceptedCourses = await db.query(`
            SELECT c.* 
            FROM course_pre_registration pr
            JOIN courses c ON pr.course_code = c.course_code
            WHERE pr.roll_no = $1 AND pr.status = 'accepted'
            ORDER BY c.slot
        `, [roll_no]);

        if (acceptedCourses.rows.length === 0) {
            return res.render('error', { 
                message: 'No accepted pre-registrations found. Please wait for instructor approval.' 
            });
        }

        // Check if student has already registered
        const existingRegistration = await db.query(
            'SELECT * FROM course_registration WHERE roll_no = $1',
            [roll_no]
        );

        if (existingRegistration.rows.length > 0) {
            return res.redirect('/registered-courses');
        }

        // Organize courses by slot
        const coursesBySlot = acceptedCourses.rows.reduce((acc, course) => {
            acc[course.slot] = acc[course.slot] || [];
            acc[course.slot].push(course);
            return acc;
        }, {});

        res.render('CourseRegistration', { 
            coursesBySlot,
            student: req.session.user
        });
    } catch (err) {
        console.error('Course registration error:', err);
        res.status(500).render('error', { message: err.message });
    }
});

app.post('/submit-registration', requireAuth, async (req, res) => {
    try {
        await db.query('BEGIN');
        const { roll_no } = req.session.user;

        // Check registration attempt count
        const registrationCheck = await db.query(
            'SELECT registration_count FROM students WHERE roll_no = $1',
            [roll_no]
        );

        if (registrationCheck.rows[0].registration_count >= 1) {
            throw new Error('You have already used your registration attempt for this semester.');
        }

        console.log("Request body:", req.body);

        if (!req.body.courses) {
            throw new Error('No courses selected');
        }

        // Filter out empty selections and parse course data
        const selectedCourses = (Array.isArray(req.body.courses) ? req.body.courses : [req.body.courses])
            .filter(code => code && code.trim())
            .map(code => {
                const [courseCode, slot, credit] = code.split('|');
                return { courseCode, slot, credit: parseInt(credit) || 0 };
            });

        if (selectedCourses.length === 0) {
            throw new Error('No valid courses selected');
        }

        // Calculate total credits
        const totalCredits = selectedCourses.reduce((sum, course) => sum + course.credit, 0);
        if (totalCredits < 12 || totalCredits > 25) {
            throw new Error(`Total credits (${totalCredits}) must be between 12 and 25`);
        }

        // Verify selected courses are pre-registered and accepted
        const verificationResult = await db.query(`
            SELECT course_code 
            FROM course_pre_registration
            WHERE roll_no = $1 
            AND course_code = ANY($2)
            AND status = 'accepted'
        `, [roll_no, selectedCourses.map(c => c.courseCode)]);

        if (verificationResult.rows.length !== selectedCourses.length) {
            throw new Error('Some selected courses were not pre-registered or accepted');
        }

        // Update registration count before inserting courses
        await db.query(`
            UPDATE students 
            SET registration_count = registration_count + 1 
            WHERE roll_no = $1
        `, [roll_no]);

        // Insert registrations
        for (const course of selectedCourses) {
            await db.query(`
                INSERT INTO course_registration (roll_no, course_code, slot)
                VALUES ($1, $2, $3)
            `, [roll_no, course.courseCode, course.slot]);
        }

        await db.query('COMMIT');
        res.redirect('/registered-courses');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Registration error:', err);
        res.status(500).render('error', { 
            message: `Registration failed: ${err.message}` 
        });
    }
});

// 4. Registered Courses
app.get('/registered-courses', requireAuth, async (req, res) => {
    try {
        const { roll_no } = req.session.user;

        // Get registered courses with full course details and credit total
        const result = await db.query(`
            SELECT 
                cr.roll_no,
                cr.course_code,
                c.course_name,
                c.instructor_name,
                c.slot,
                c.credit,
                c.ltpc,
                SUM(c.credit::integer) OVER() as total_credits
            FROM course_registration cr
            JOIN courses c ON cr.course_code = c.course_code
            WHERE cr.roll_no = $1
            ORDER BY c.slot
        `, [roll_no]);

        if (result.rows.length === 0) {
            return res.render('RegisteredCourses', { 
                courses: [],
                student: req.session.user,
                message: 'No courses registered yet. Please complete course registration first.'
            });
        }

        res.render('RegisteredCourses', { 
            courses: result.rows,
            student: req.session.user,
            totalCredits: result.rows[0].total_credits
        });
    } catch (err) {
        console.error('Error fetching registered courses:', err);
        res.status(500).render('error', { 
            message: 'Error loading registered courses: ' + err.message 
        });
    }
});

// Instructor Dashboard
app.get('/instructor-dashboard', requireAuth, async (req, res) => {
    try {
        if (!req.session.user.instructor_id) {
            return res.status(403).render('error', { 
                message: 'Access denied: Instructor only area' 
            });
        }

        console.log('Instructor ID:', req.session.user.instructor_id);

        const result = await db.query(`
            SELECT 
                c.course_code,
                c.course_name,
                c.slot,
                CASE 
                    WHEN COUNT(pr.id) = 0 THEN '[]'::json
                    ELSE json_agg(
                        CASE 
                            WHEN pr.id IS NOT NULL THEN
                                json_build_object(
                                    'id', pr.id,
                                    'student_name', s.student_name,
                                    'roll_no', pr.roll_no,
                                    'status', pr.status,
                                    'submission_count', s.submission_count,
                                    'submitted_at', pr.created_at
                                )
                            ELSE NULL
                        END
                    )
                END as requests
            FROM courses c
            LEFT JOIN course_pre_registration pr ON c.course_code = pr.course_code
            LEFT JOIN students s ON pr.roll_no = s.roll_no
            WHERE c.instructor_id = $1
            GROUP BY c.course_code, c.course_name, c.slot
            ORDER BY c.slot, c.course_code
        `, [req.session.user.instructor_id]);

        console.log('Query result:', result.rows);

        res.render('InstructorDashboard', {
            courses: result.rows,
            instructor: req.session.user
        });
    } catch (err) {
        console.error('Dashboard error:', err);
        res.status(500).render('error', { message: err.message });
    }
});

// Update Pre-Registration Status
app.put('/update-status/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        // Verify instructor has authority without using course_code
        const verification = await db.query(`
            SELECT c.instructor_id, pr.roll_no
            FROM course_pre_registration pr
            JOIN courses c ON pr.course_code = c.course_code
            WHERE pr.id = $1 AND c.instructor_id = $2
        `, [id, req.session.user.instructor_id]);
        
        if (verification.rows.length === 0) {
            throw new Error('Unauthorized status update');
        }

        await db.query(`
            UPDATE course_pre_registration
            SET status = $1
            WHERE id = $2
        `, [status, id]);


        
        // res.redirect('/instructor-dashboard');
    } catch (err) {
        console.error('Status update error:', err);
        res.status(500).render('error', { message: err.message });
    }
});

// Add this new route for getting registered students
app.get('/get-registered-students', requireAuth, async (req, res) => {
    try {
        if (!req.session.user.instructor_id) {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = await db.query(`
            SELECT 
                c.course_code,
                c.course_name,
                json_agg(json_build_object(
                    'student_name', s.student_name,
                    'roll_no', s.roll_no,
                    'slot', cr.slot
                )) as students
            FROM courses c
            LEFT JOIN course_registration cr ON c.course_code = cr.course_code
            LEFT JOIN students s ON cr.roll_no = s.roll_no
            WHERE c.instructor_id = $1
            GROUP BY c.course_code, c.course_name
        `, [req.session.user.instructor_id]);

        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching registered students:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add route for admin to view all registrations
app.get('/admin/course-registrations', requireAuth, async (req, res) => {
    try {
        if (req.session.user.role !== 'admin') {
            return res.status(403).render('error', { 
                message: 'Access denied: Admin only area' 
            });
        }

        const result = await db.query(`
            SELECT 
                c.course_code,
                c.course_name,
                c.instructor_name,
                COUNT(cr.roll_no) as student_count,
                json_agg(json_build_object(
                    'student_name', s.student_name,
                    'roll_no', s.roll_no,
                    'branch_code', s.student_branch_code
                )) as students
            FROM courses c
            LEFT JOIN course_registration cr ON c.course_code = cr.course_code
            LEFT JOIN students s ON cr.roll_no = s.roll_no
            GROUP BY c.course_code, c.course_name, c.instructor_name
            ORDER BY c.course_code
        `);

        res.render('AdminCourseRegistrations', { courses: result.rows });
    } catch (err) {
        console.error('Error fetching course registrations:', err);
        res.status(500).render('error', { message: err.message });
    }
});
// View Students
app.get("/viewstudents", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM students");
    res.render("viewstudents", { students: result.rows });
  } catch (err) {
    console.error("Error fetching students:", err.stack);
    res.status(500).send("Error retrieving student data");
  }
});

// View Faculty
app.get("/viewfaculty", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM instructors");
    res.render("viewfaculty", { faculty: result.rows });
  } catch (err) {
    console.error("Error fetching faculty:", err.stack);
    res.status(500).send("Error retrieving faculty data");
  }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err.name === 'UnauthorizedError') {
        return res.status(401).render('error', { 
            message: 'Authentication required. Please login.' 
        });
    }
    res.status(500).render('error', { 
        message: 'Something went wrong!' 
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
