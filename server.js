const express = require("express");
const mysql = require("mysql2");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

dotenv.config();

const app = express();
const PORT = 3007;
const SECRET_KEY = process.env.JWT_SECRET || "nirmay3093";

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("uploads"));
app.use("/uploads", express.static("uploads"));

const uploadDir = "./uploads/";
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, "uploads/"),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage: storage });

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "upload",
});

db.connect((err) => {
    if (err) throw err;
    console.log("MySQL Connected...");
});

const authenticateJWT = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect("/login");
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.redirect("/login");
        }
        req.user = user;
        next();
    });
};

app.get("/", (req, res) => {
    res.redirect("/login");
});
app.get("/register", (req, res) => {
    res.render("register");
});
app.get("/login", (req, res) => {
    res.render("login", { error: null });
});
app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/login");
});
app.get("/users", authenticateJWT, (req, res) => {
    const sql = "SELECT id, name, email, created_at FROM users";
    db.query(sql, (err, result) => {
        if (err) {
            return res.status(500).send("Database error");
        }

        res.render("users", {
            users: result,
            loggedInUserId: req.user.id
        })
    });
});
app.get("/users/:id", authenticateJWT, (req, res) => {
    const loggedInUserId = req.user.id;
    const requestedUserId = parseInt(req.params.id);

    if (loggedInUserId !== requestedUserId) {
        return res.status(403).send("Access denied: You can only view your own profile.");
    }

    const userQuery = "SELECT * FROM users WHERE id = ?";
    const filesQuery = "SELECT * FROM upload WHERE user_id = ?";

    db.query(userQuery, [requestedUserId], (err, userResults) => {
        if (err || userResults.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        db.query(filesQuery, [requestedUserId], (err, fileResults) => {
            if (err) {
                return res.status(500).json({ error: "Database error" });
            }
            res.render("singleUser", { user: userResults[0], files: fileResults });
        });
    });
});
app.get("/uploads", authenticateJWT, (req, res) => {
    const sql = `
        SELECT users.id AS user_id, users.name, upload.file_name 
        FROM upload 
        INNER JOIN users ON upload.user_id = users.id
    `;

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        res.render("uploads", { uploads: results });
    });
});
app.get("/createUser", authenticateJWT, (req, res) => {
    res.render("add-user");
});
app.get("/forgot-password", (req, res) => {
    res.render("forgot-password", { error: null });
});


app.post("/users", authenticateJWT, (req, res) => {
    if (!req.user.is_admin) {
        return res.status(403).send("Access denied: Only admins can add users.");
    }

    const { name, email } = req.body;
    if (!name || !email) {
        return res.status(400).json({ error: "Name and email are required" });
    }

    const sql = "INSERT INTO users (name, email) VALUES (?, ?)";
    db.query(sql, [name, email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        res.redirect("/users");
    });
});
app.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], (err, results) => {
        if (err || results.length === 0) {
            return res.render("forgot-password", { error: "Email not found" });
        }

        const token = crypto.randomBytes(32).toString("hex");
        const expireTime = new Date(Date.now() + 3600000);

        const updateQuery = `
            UPDATE users 
            SET reset_token = ?, reset_token_expiry = ? 
            WHERE email = ?
        `;

        db.query(updateQuery, [token, expireTime, email], (err) => {
            if (err) {
                return res.render("forgot-password", { error: "Database error" });
            }

            // Send email with reset link
            const transporter = nodemailer.createTransport({
                service: "gmail",
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const resetLink = `http://localhost:${PORT}/reset-password?token=${token}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: "Password Reset",
                html: `
                    <p>You requested a password reset.</p>
                    <p>Click <a href="${resetLink}">here</a> to reset your password.</p>
                    <p>This link is valid for 1 hour.</p>
                `,
            };

            transporter.sendMail(mailOptions, (error) => {
                if (error) {
                    console.error("Email send error:", error);
                    return res.render("forgot-password", { error: "Error sending email" });
                }

                res.render("forgot-password", { error: "Reset link sent. Check your email!" });
            });
        });
    });
});
app.post("/register", async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
        return res.render("register", { error: "All fields are required" });
    }

    if (password !== confirmPassword) {
        return res.render("register", { error: "Passwords do not match" });
    }

    try {

        const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
        db.query(checkEmailQuery, [email], async (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.render("register", { error: "Database error. Please try again." });
            }

            if (results.length > 0) {

                return res.render("register", { error: "Email is already registered. Please use a different email." });
            }


            const hashedPassword = await bcrypt.hash(password, 10);

            const insertQuery = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
            db.query(insertQuery, [name, email, hashedPassword], (err, result) => {
                if (err) {
                    console.error("Database error:", err);
                    return res.render("register", { error: "Error creating account. Please try again." });
                }
                res.redirect("/");
            });
        });

    } catch (error) {
        console.error("Error:", error);
        res.render("register", { error: "Something went wrong. Please try again." });
    }
});
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {

        const [rows, fields] = await db.promise().execute("SELECT * FROM users WHERE email = ?", [email]);

        if (rows.length === 0) {
            return res.render("login", { error: "Invalid credentials" });
        }

        const user = rows[0];


        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.render("login", { error: "Invalid credentials" });
        }


        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
        res.cookie("token", token, { httpOnly: true });

        res.redirect("/users");
    } catch (error) {
        console.error("Database error:", error);
        res.render("login", { error: "Something went wrong. Please try again." });
    }
});
app.post("/upload", authenticateJWT, upload.single("file"), (req, res) => {
    const userId = req.user.id;  // Current logged-in user ID

    if (!req.file) {
        return res.status(400).json({ error: "File is required" });
    }

    const file_name = req.file.filename;

    const sql = "INSERT INTO upload (user_id, file_name) VALUES (?, ?)";
    db.query(sql, [userId, file_name], (err, result) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        res.redirect(`/users/${userId}`);
    });
});
app.post("/users/:id/delete", authenticateJWT, (req, res) => {
    const loggedInUserId = req.user.id;
    const userIdToDelete = parseInt(req.params.id);

    if (loggedInUserId !== userIdToDelete) {
        return res.status(403).send("Access denied: You can only delete your own account.");
    }

    const getFilesQuery = "SELECT file_name FROM upload WHERE user_id = ?";
    db.query(getFilesQuery, [userIdToDelete], (err, fileResults) => {
        fileResults.forEach((file) => {
            const filePath = path.join(__dirname, "uploads", file.file_name);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        });

        const deleteFilesQuery = "DELETE FROM upload WHERE user_id = ?";
        db.query(deleteFilesQuery, [userIdToDelete], () => {
            const deleteUserQuery = "DELETE FROM users WHERE id = ?";
            db.query(deleteUserQuery, [userIdToDelete], () => {
                res.redirect("/logout");
            });
        });
    });
});
app.post("/delete-file", authenticateJWT, (req, res) => {
    const { fileName } = req.body;
    const userId = req.user.id;

    if (!fileName) {
        return res.status(400).send("File name is required.");
    }
    const sql = "SELECT * FROM upload WHERE file_name = ? AND user_id = ?";
    db.query(sql, [fileName, userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Database error.");
        }

        if (results.length === 0) {
            return res.status(403).send("You can only delete your own files.");
        }

        const filePath = path.join(__dirname, "uploads", fileName);


        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }


        const deleteQuery = "DELETE FROM upload WHERE file_name = ? AND user_id = ?";
        db.query(deleteQuery, [fileName, userId], (err) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).send("Failed to delete file from database.");
            }

            res.redirect(`/users/${userId}`);
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}...`);
});
