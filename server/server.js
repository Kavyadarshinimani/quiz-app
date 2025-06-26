// server.js
// This file sets up the Express server, connects to MongoDB, defines Mongoose schemas,
// handles user authentication (register, login) with JWT, and manages quiz operations.

// --- Module Imports ---
const express = require('express'); // Web framework for Node.js
const mongoose = require('mongoose'); // MongoDB object modeling tool
const bcrypt = require('bcryptjs'); // Library for hashing passwords
const jwt = require('jsonwebtoken'); // Library for creating and verifying JSON Web Tokens
const cors = require('cors'); // Middleware for enabling Cross-Origin Resource Sharing
const dotenv = require('dotenv'); // Loads environment variables from a .env file

// Load environment variables from .env file
dotenv.config();

// --- Express App Initialization ---
const app = express(); // Create an Express application instance

// --- Middleware Setup ---
app.use(express.json()); // Enable parsing JSON request bodies
app.use(cors()); // Enable CORS for all routes, allowing frontend to communicate

// --- MongoDB Connection ---
const mongoURI = process.env.MONGO_URI; // Get MongoDB connection string from environment variables

mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB connected successfully')) // Log success on connection
    .catch(err => console.error('MongoDB connection error:', err)); // Log error if connection fails

// --- Mongoose Schemas ---

// User Schema: Defines the structure for user documents in MongoDB
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true }, // User's email, must be unique
    password: { type: String, required: true }, // Hashed password
});

// Middleware to hash password before saving user
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) { // Only hash if password field is modified
        return next();
    }
    const salt = await bcrypt.genSalt(10); // Generate a salt for hashing
    this.password = await bcrypt.hash(this.password, salt); // Hash the password
    next();
});

const User = mongoose.model('User', UserSchema); // Create User model from schema

// Question Schema: Defines the structure for individual questions within a quiz
const QuestionSchema = new mongoose.Schema({
    questionText: { type: String, required: true }, // The text of the question
    options: [{ type: String, required: true }], // Array of possible answer options
    correctAnswer: { type: String, required: true }, // The correct answer option
});

// Quiz Schema: Defines the structure for quiz documents in MongoDB
const QuizSchema = new mongoose.Schema({
    title: { type: String, required: true }, // Title of the quiz
    questions: [QuestionSchema], // Array of questions in the quiz
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } // User who created the quiz
});

const Quiz = mongoose.model('Quiz', QuizSchema); // Create Quiz model from schema

// --- JWT Authentication Middleware ---
// This middleware protects routes, ensuring only authenticated users can access them.
const auth = (req, res, next) => {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check if no token
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token using secret key
        req.user = decoded.user; // Attach user information from token to request object
        next(); // Proceed to the next middleware/route handler
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' }); // Return error if token is invalid
    }
};

// --- API Routes ---

// --- User Authentication Routes ---

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body; // Destructure email and password from request body

    try {
        // Check if user already exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Create new user instance
        user = new User({ email, password });

        await user.save(); // Save the new user to the database (password gets hashed by pre-save middleware)

        // Create JWT payload
        const payload = {
            user: {
                id: user.id // User's ID from MongoDB
            }
        };

        // Sign the JWT and send it back to the client
        jwt.sign(
            payload,
            process.env.JWT_SECRET, // Secret key from environment variables
            { expiresIn: '1h' }, // Token expires in 1 hour
            (err, token) => {
                if (err) throw err; // Throw error if signing fails
                res.json({ token, user: { id: user.id, email: user.email } }); // Send token and user info
            }
        );
    } catch (err) {
        console.error(err.message); // Log any server errors
        res.status(500).send('Server Error'); // Send generic server error response
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body; // Destructure email and password from request body

    try {
        // Check if user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' }); // User not found
        }

        // Compare provided password with hashed password in database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' }); // Passwords do not match
        }

        // Create JWT payload
        const payload = {
            user: {
                id: user.id
            }
        };

        // Sign the JWT and send it back
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, user: { id: user.id, email: user.email } });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// --- Quiz Routes ---

// @route   POST /api/quizzes
// @desc    Create a new quiz
// @access  Private (requires authentication)
app.post('/api/quizzes', auth, async (req, res) => {
    const { title, questions } = req.body; // Get quiz title and questions from body
    try {
        const newQuiz = new Quiz({
            title,
            questions,
            createdBy: req.user.id // Set createdBy to the ID of the authenticated user
        });
        const quiz = await newQuiz.save(); // Save the new quiz
        res.json(quiz); // Send the created quiz back
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/quizzes
// @desc    Get all quizzes
// @access  Public (can be accessed by anyone)
app.get('/api/quizzes', async (req, res) => {
    try {
        const quizzes = await Quiz.find().populate('createdBy', 'email'); // Find all quizzes and populate user email
        res.json(quizzes); // Send array of quizzes
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/quizzes/:id
// @desc    Get a single quiz by ID
// @access  Public
app.get('/api/quizzes/:id', async (req, res) => {
    try {
        const quiz = await Quiz.findById(req.params.id); // Find quiz by ID from URL params
        if (!quiz) {
            return res.status(404).json({ msg: 'Quiz not found' });
        }
        res.json(quiz); // Send the found quiz
    } catch (err) {
        console.error(err.message);
        if (err.kind === 'ObjectId') { // Handle invalid MongoDB ID format
            return res.status(400).json({ msg: 'Quiz not found' });
        }
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/quizzes/:id/submit
// @desc    Submit answers for a quiz and calculate score
// @access  Private
app.post('/api/quizzes/:id/submit', auth, async (req, res) => {
    const { answers } = req.body; // Expects an array of objects: [{ questionId: "...", userAnswer: "..." }]
    try {
        const quiz = await Quiz.findById(req.params.id);
        if (!quiz) {
            return res.status(404).json({ msg: 'Quiz not found' });
        }

        let score = 0;
        let correctAnswersCount = 0;
        let totalQuestions = quiz.questions.length;
        const results = [];

        quiz.questions.forEach(question => {
            const userAnswerObj = answers.find(a => a.questionId === question._id.toString());
            const userAnswer = userAnswerObj ? userAnswerObj.userAnswer : null;

            const isCorrect = userAnswer === question.correctAnswer;
            if (isCorrect) {
                score += 1;
                correctAnswersCount += 1;
            }
            results.push({
                questionId: question._id,
                questionText: question.questionText,
                userAnswer: userAnswer,
                correctAnswer: question.correctAnswer,
                isCorrect: isCorrect
            });
        });

        res.json({
            score: score,
            correctAnswers: correctAnswersCount,
            totalQuestions: totalQuestions,
            results: results
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// --- Server Listening ---
const PORT = process.env.PORT || 5000; // Get port from environment or use 5000 as default
app.listen(PORT, () => console.log(`Server started on port ${PORT}`)); // Start server and log port
