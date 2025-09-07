const express = require('express');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
// const cors = require('cors');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // ADD THIS - Missing fs import
const http = require('http');
const { Server } = require('socket.io');
const cookieParser = require('cookie-parser');
const app = express();
const PORT = process.env.PORT || 5000;
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || ["http://localhost:3000", "http://localhost:5173", 'https://freelance-saa-s-jvxs.vercel.app'],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    credentials: true
  }
});

const createUploadDirs = () => {
  const dirs = ['uploads', 'uploads/profiles'];
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`Created directory: ${dir}`);
    }
  });
};
createUploadDirs();
// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// app.use(cors({
//   origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173','*'], // Add your frontend URL
//   methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization'],
//   credentials: true
// }));
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173', 'https://freelance-saa-s-jvxs.vercel.app', '*'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  next();
});
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Create specific folder for profile photos
    const uploadPath = file.fieldname === 'profilePhoto' ? 'uploads/profiles' : 'uploads';

    // Ensure directory exists
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }

    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Create unique filename with timestamp and original extension
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const fileFilter = (req, file, cb) => {
  // Different filters for different file types
  if (file.fieldname === 'profilePhoto') {
    // Accept only image files for profile photos
    const allowedImageTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedImageTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedImageTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files (jpeg, jpg, png, gif, webp) are allowed for profile photos'));
    }
  } else {
    // Accept documents and images for other uploads
    const allowedFileTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedFileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedFileTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only images, PDFs, and documents are allowed'));
    }
  }
};
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB max for profile photos
  },
  fileFilter: fileFilter
});
// Make uploads folder publicly accessible
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Connect to MongoDB
// mongoose.connect('mongodb://localhost:27017/freelance-platform', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// })
mongoose.connect('mongodb+srv://santhiraju32_db_user:ErW8GpGpfXEZwW97@cluster0.uxfnhgz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})

  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err));

// UPDATED User Schema - Remove duplicate index
const userSchema = new mongoose.Schema({
  // Basic Info
  fullName: {
    type: String,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true, // This creates an index automatically
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },

  // Profile Photo
  profilePhoto: {
    type: String, // Store the file path/URL
    default: null
  },

  // Professional Info
  title: {
    type: String,
    trim: true
  },
  bio: {
    type: String,
    trim: true
  },
  hourlyRate: {
    type: Number,
    min: 0
  },
  location: {
    type: String,
    trim: true
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other', 'Prefer not to say'],
    trim: true
  },
  availabilityPerWeek: {
    type: String,
    trim: true
  },

  // Skills
  skills: [{
    type: String,
    trim: true
  }],

  // Languages
  languages: [{
    name: {
      type: String,
      trim: true
    },
    proficiency: {
      type: String,
      enum: ['Basic', 'Conversational', 'Fluent', 'Native'],
      trim: true
    }
  }],

  // Experience
  experience: [{
    company: {
      type: String,
      trim: true
    },
    position: {
      type: String,
      trim: true
    },
    years: {
      type: String,
      trim: true
    },
    description: {
      type: String,
      trim: true
    }
  }],

  // Education
  education: [{
    institution: {
      type: String,
      trim: true
    },
    degree: {
      type: String,
      trim: true
    },
    years: {
      type: String,
      trim: true
    }
  }],

  // Certifications
  certifications: [{
    name: {
      type: String,
      trim: true
    },
    issuer: {
      type: String,
      trim: true
    },
    date: {
      type: String,
      trim: true
    }
  }],

  // Portfolio Projects
  portfolioProjects: [{
    name: {
      type: String,
      trim: true
    },
    description: {
      type: String,
      trim: true
    },
    technologies: [{
      type: String,
      trim: true
    }],
    link: {
      type: String,
      trim: true
    }
  }],

  // Reviews (you might want to create a separate Reviews model later)
  reviews: [{
    clientName: String,
    clientAvatar: String,
    rating: {
      type: Number,
      min: 1,
      max: 5
    },
    comment: String,
    date: {
      type: Date,
      default: Date.now
    }
  }],

  // Account Info
  role: {
    type: String,
    enum: ['user', 'admin', 'client', 'freelancer'],
    default: 'user'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date
}, {
  timestamps: true // This adds createdAt and updatedAt fields
});
userSchema.index({ 'skills': 1 });
userSchema.index({ 'location': 1 });

// Virtual for profile completion percentage
userSchema.virtual('profileCompleteness').get(function () {
  let completedFields = 0;
  const totalFields = 10; // Adjust based on required fields

  if (this.fullName) completedFields++;
  if (this.email) completedFields++;
  if (this.title) completedFields++;
  if (this.bio) completedFields++;
  if (this.location) completedFields++;
  if (this.profilePhoto) completedFields++;
  if (this.skills && this.skills.length > 0) completedFields++;
  if (this.experience && this.experience.length > 0) completedFields++;
  if (this.education && this.education.length > 0) completedFields++;
  if (this.hourlyRate) completedFields++;

  return Math.round((completedFields / totalFields) * 100);
});

// Ensure virtual fields are serialized
userSchema.set('toJSON', { virtuals: true });

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Project Schema
const projectSchema = new mongoose.Schema({
  title: { type: String, required: true },
  email: { type: String, required: true },
  description: { type: String, required: true },
  budget_from: { type: Number, required: true },
  budget_to: { type: Number, required: true },
  project_type: { type: String, required: true },
  project_duration: { type: String, required: true },
  req_skills: {
    type: [String], // This makes it an array of strings
    required: true
  },
  status: {
    type: String,
    enum: ["pending", "in-progress", "completed"],
    default: "pending",
  },
  project_id: {
    type: String,
    required: true,
    unique: true
  }

}, { timestamps: true });

const Project = mongoose.model('Project', projectSchema);
// Task Schema
const taskSchema = new mongoose.Schema({
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  bid: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Bid',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'rejected'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  dueDate: {
    type: Date
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  attachments: [{
    filename: String,
    originalName: String,
    path: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  comments: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    content: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  completionProof: {
    description: String,
    attachments: [{
      filename: String,
      originalName: String,
      path: String,
      uploadedAt: {
        type: Date,
        default: Date.now
      }
    }],
    submittedAt: Date
  },
  approvedAt: Date,
  rejectedReason: String
}, {
  timestamps: true
});

// Index for better query performance
taskSchema.index({ project: 1, status: 1 });
taskSchema.index({ assignedTo: 1, status: 1 });
taskSchema.index({ assignedBy: 1 });

const Task = mongoose.model('Task', taskSchema);
// Bid Schema
const bidSchema = new mongoose.Schema({
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  freelancer: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  deliveryTime: {
    type: String,
    required: true
  },
  coverLetter: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

const Bid = mongoose.model('Bid', bidSchema);

const bookmarkSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  userEmail: {
    type: String,
    required: true
  },
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  projectId: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

// Create compound index to prevent duplicate bookmarks
bookmarkSchema.index({ user: 1, project: 1 }, { unique: true });

const Bookmark = mongoose.model('Bookmark', bookmarkSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  conversation: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation',
    required: true
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  content: {
    type: String,
    required: true
  },
  attachment: {
    type: String
  },
  read: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

const Message = mongoose.model('Message', messageSchema);

// Conversation Schema
const conversationSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project'
  },
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  }
}, {
  timestamps: true
});
const Conversation = mongoose.model('Conversation', conversationSchema);
// Middleware for JWT authentication
const verifyToken = async (req, res, next) => {
  try {
    let token;

    // Get token from cookies or headers
    if (req.cookies.token) {
      token = req.cookies.token;
    } else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');

    // Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User no longer exists'
      });
    }

    // Add user to request object
    req.user = {
      id: user._id,
      role: user.role
    };

    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({
      success: false,
      message: 'Not authorized to access this route',
      error: error.message
    });
  }
};
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email already exists'
      });
    }

    // Create new user
    const user = await User.create({
      fullName,
      email,
      password,
      role: role || 'client'
    });

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '30d' }
    );

    // Remove password from response
    user.password = undefined;

    // Send token in cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user,
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.message
    });
  }
});
// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check if password is correct
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || 'your_jwt_secret',
      { expiresIn: '30d' }
    );

    // Remove password from response
    user.password = undefined;

    // Send token in cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.status(200).json({
      success: true,
      message: 'Logged in successfully',
      data: {
        user,
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
});
// Logout User
app.get('/api/auth/logout', (req, res) => {
  res.cookie('token', '', {
    httpOnly: true,
    expires: new Date(0),
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });

  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});
app.post('/api/post_project', async (req, res) => {
  try {
    const {
      title,
      description,
      budget_from,
      budget_to,
      project_type,
      project_duration,
      email,
      req_skills
    } = req.body;

    const project_id = uuidv4();

    const newProject = await Project.create({
      project_id,
      title,
      description,
      budget_from,
      budget_to,
      project_type,
      project_duration,
      req_skills,
      email
    });

    res.status(201).json({
      message: 'Project created successfully',
      project: newProject
    });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// get all projects
app.get('/api/get_projects', async (req, res) => {
  try {
    const projects = await Project.find().sort({ createdAt: -1 }); // Latest first
    res.status(200).json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
// UPDATED Profile routes with better error handling
app.post('/api/profile', verifyToken, upload.single('profilePhoto'), async (req, res) => {
  try {
    const {
      profile_title,
      hourlyRate,
      location,
      languages,
      aboutDescription,
      skillsList,
      experience,
      education,
      certifications,
      availabilityPerWeek,
      projectPortfolio,
      name,
      email,
      gender
    } = req.body;

    // All fields are optional - user can save partial profile
    const profileData = {};

    if (name) profileData.fullName = name;
    if (email) profileData.email = email;
    if (profile_title) profileData.title = profile_title;
    if (hourlyRate !== undefined) profileData.hourlyRate = hourlyRate;
    if (location) profileData.location = location;
    if (aboutDescription) profileData.bio = aboutDescription;
    if (Array.isArray(skillsList)) profileData.skills = skillsList;
    if (gender) profileData.gender = gender;

    // Handle profile photo upload
    if (req.file) {
      // Get current user to delete old profile photo
      const currentUser = await User.findById(req.user.id);

      // Delete old profile photo if exists
      if (currentUser && currentUser.profilePhoto) {
        const oldPhotoPath = path.join(__dirname, currentUser.profilePhoto.replace('/uploads/', 'uploads/'));
        try {
          if (fs.existsSync(oldPhotoPath)) {
            fs.unlinkSync(oldPhotoPath);
            console.log('Deleted old profile photo:', oldPhotoPath);
          }
        } catch (err) {
          console.error('Error deleting old photo:', err);
        }
      }

      // Save new profile photo path
      profileData.profilePhoto = `/uploads/profiles/${req.file.filename}`;
    }

    // Process languages array
    if (Array.isArray(languages)) {
      profileData.languages = languages.map(lang => ({
        name: lang.name || lang.language || '',
        proficiency: lang.proficiency || lang.level || ''
      }));
    }

    // Process experience array
    if (Array.isArray(experience)) {
      profileData.experience = experience.map(exp => ({
        company: exp.organisation || exp.company || '',
        position: exp.role || exp.position || '',
        years: exp.fromDate && exp.toDate ? `${exp.fromDate} - ${exp.toDate}` : '',
        description: exp.description || ''
      }));
    }

    // Process education array
    if (Array.isArray(education)) {
      profileData.education = education.map(edu => ({
        institution: edu.university || edu.institution || '',
        degree: edu.department || edu.branch || edu.degree || '',
        years: edu.fromYear && edu.toYear ? `${edu.fromYear} - ${edu.toYear}` : ''
      }));
    }

    // Process certifications array
    if (Array.isArray(certifications)) {
      profileData.certifications = certifications.map(cert => ({
        name: cert.certificateName || cert.name || '',
        issuer: cert.provider || cert.issuer || '',
        date: cert.issuedDate || cert.date || ''
      }));
    }

    // Process portfolio projects array
    if (Array.isArray(projectPortfolio)) {
      profileData.portfolioProjects = projectPortfolio.map(project => ({
        name: project.title || project.name || '',
        description: project.description || '',
        technologies: Array.isArray(project.skills) ? project.skills : [],
        link: project.link || ''
      }));
    }

    // Add availability per week as a custom field
    if (availabilityPerWeek) {
      profileData.availabilityPerWeek = availabilityPerWeek;
    }

    // Find and update user profile
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      profileData,
      {
        new: true,
        runValidators: true
      }
    ).select('-password'); // Exclude password from response

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);

    // Delete uploaded file if there was an error
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('Deleted uploaded file due to error:', req.file.path);
      } catch (deleteErr) {
        console.error('Error deleting uploaded file:', deleteErr);
      }
    }

    // Handle multer errors
    if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          message: 'File too large. Maximum size is 5MB.'
        });
      }
      return res.status(400).json({
        success: false,
        message: 'File upload error: ' + error.message
      });
    }

    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors
      });
    }

    // Handle duplicate email error
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Profile update failed',
      error: error.message
    });
  }
});
// GET profile endpoint to fetch user profile
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: user
      }
    });

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile',
      error: error.message
    });
  }
});
// PUT profile endpoint for updating specific fields (with photo support)
app.put('/api/profile', verifyToken, upload.single('profilePhoto'), async (req, res) => {
  try {
    const updates = req.body;

    // Remove sensitive fields that shouldn't be updated via this endpoint
    delete updates.password;
    delete updates.role;
    delete updates._id;

    // Handle profile photo upload
    if (req.file) {
      // Get current user to delete old profile photo
      const currentUser = await User.findById(req.user.id);

      // Delete old profile photo if exists
      if (currentUser && currentUser.profilePhoto) {
        const oldPhotoPath = path.join(__dirname, currentUser.profilePhoto.replace('/uploads/', 'uploads/'));
        try {
          if (fs.existsSync(oldPhotoPath)) {
            fs.unlinkSync(oldPhotoPath);
            console.log('Deleted old profile photo:', oldPhotoPath);
          }
        } catch (err) {
          console.error('Error deleting old photo:', err);
        }
      }

      // Add new profile photo path to updates
      updates.profilePhoto = `/uploads/profiles/${req.file.filename}`;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updates,
      {
        new: true,
        runValidators: true
      }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: {
        user: updatedUser
      }
    });

  } catch (error) {
    console.error('Profile update error:', error);

    // Delete uploaded file if there was an error
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('Deleted uploaded file due to error:', req.file.path);
      } catch (deleteErr) {
        console.error('Error deleting uploaded file:', deleteErr);
      }
    }

    // Handle multer errors
    if (error instanceof multer.MulterError) {
      if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          success: false,
          message: 'File too large. Maximum size is 5MB.'
        });
      }
      return res.status(400).json({
        success: false,
        message: 'File upload error: ' + error.message
      });
    }

    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Profile update failed',
      error: error.message
    });
  }
});
// DELETE profile photo endpoint
app.delete('/api/profile/photo', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Delete photo file if exists
    if (user.profilePhoto) {
      const photoPath = path.join(__dirname, user.profilePhoto.replace('/uploads/', 'uploads/'));
      try {
        if (fs.existsSync(photoPath)) {
          fs.unlinkSync(photoPath);
          console.log('Deleted profile photo:', photoPath);
        }
      } catch (err) {
        console.error('Error deleting photo file:', err);
      }

      // Remove profilePhoto from user document
      user.profilePhoto = null;
      await user.save();
    }

    res.status(200).json({
      success: true,
      message: 'Profile photo deleted successfully'
    });

  } catch (error) {
    console.error('Delete profile photo error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete profile photo',
      error: error.message
    });
  }
});
// Enhanced API endpoint to fetch all projects with user profile data
// app.get('/api/projects/with-profiles', async (req, res) => {
//   try {
//     // Fetch all projects sorted by creation date (latest first)
//     const projects = await Project.find().sort({ createdAt: -1 });

//     // If no projects found
//     if (!projects || projects.length === 0) {
//       return res.status(200).json({
//         success: true,
//         message: 'No projects found',
//         data: []
//       });
//     }

//     // Enhance each project with user profile data
//     const enhancedProjects = await Promise.all(
//       projects.map(async (project) => {
//         try {
//           // Find user by email from the project
//           const user = await User.findOne({ email: project.email })
//             .select('fullName profilePhoto reviews email title location skills');

//           // Calculate average rating from reviews
//           let averageRating = 0;
//           let totalReviews = 0;

//           if (user && user.reviews && user.reviews.length > 0) {
//             const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
//             totalReviews = user.reviews.length;
//             averageRating = (totalRating / totalReviews).toFixed(1);
//           }

//           // Convert project to object and add user data
//           const projectObj = project.toObject();

//           return {
//             ...projectObj,
//             userProfile: user ? {
//               id: user._id,
//               fullName: user.fullName,
//               email: user.email,
//               title: user.title,
//               location: user.location,
//               skills: user.skills,
//               profilePhoto: user.profilePhoto,
//               rating: {
//                 average: parseFloat(averageRating),
//                 totalReviews: totalReviews
//               }
//             } : {
//               id: null,
//               fullName: 'Unknown User',
//               email: project.email,
//               title: null,
//               location: null,
//               skills: [],
//               profilePhoto: null,
//               rating: {
//                 average: 0,
//                 totalReviews: 0
//               }
//             }
//           };
//         } catch (userError) {
//           console.error(`Error fetching user data for project ${project._id}:`, userError);

//           // Return project with default user data if user fetch fails
//           const projectObj = project.toObject();
//           return {
//             ...projectObj,
//             userProfile: {
//               id: null,
//               fullName: 'Unknown User',
//               email: project.email,
//               title: null,
//               location: null,
//               skills: [],
//               profilePhoto: null,
//               rating: {
//                 average: 0,
//                 totalReviews: 0
//               }
//             }
//           };
//         }
//       })
//     );

//     res.status(200).json({
//       success: true,
//       message: 'Projects fetched successfully',
//       data: enhancedProjects,
//       count: enhancedProjects.length
//     });

//   } catch (error) {
//     console.error('Error fetching projects with profiles:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch projects',
//       error: error.message
//     });
//   }
// });
// Alternative endpoint with pagination and filtering options
app.get('/api/projects/enhanced', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      project_type,
      skills,
      budget_min,
      budget_max,
      location,
      sort = 'createdAt',
      order = 'desc'
    } = req.query;

    // Build filter object
    const filter = {};

    if (project_type) {
      filter.project_type = project_type;
    }

    if (skills) {
      // Split skills by comma and create regex search
      const skillsArray = skills.split(',').map(skill => skill.trim());
      filter.req_skills = { $in: skillsArray.map(skill => new RegExp(skill, 'i')) };
    }

    if (budget_min || budget_max) {
      filter.$and = [];
      if (budget_min) {
        filter.$and.push({ budget_from: { $gte: parseInt(budget_min) } });
      }
      if (budget_max) {
        filter.$and.push({ budget_to: { $lte: parseInt(budget_max) } });
      }
    }

    // Build sort object
    const sortObj = {};
    sortObj[sort] = order === 'desc' ? -1 : 1;

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get total count for pagination
    const totalProjects = await Project.countDocuments(filter);

    // Fetch projects with filters, sorting, and pagination
    const projects = await Project.find(filter)
      .sort(sortObj)
      .skip(skip)
      .limit(parseInt(limit));

    if (!projects || projects.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'No projects found',
        data: [],
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalProjects / parseInt(limit)),
          totalProjects: totalProjects,
          hasNext: false,
          hasPrev: false
        }
      });
    }

    // Enhance projects with user profile data
    const enhancedProjects = await Promise.all(
      projects.map(async (project) => {
        try {
          const user = await User.findOne({ email: project.email })
            .select('fullName profilePhoto reviews email title location skills hourlyRate');

          let averageRating = 0;
          let totalReviews = 0;

          if (user && user.reviews && user.reviews.length > 0) {
            const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
            totalReviews = user.reviews.length;
            averageRating = (totalRating / totalReviews).toFixed(1);
          }

          const projectObj = project.toObject();

          return {
            ...projectObj,
            userProfile: user ? {
              id: user._id,
              fullName: user.fullName,
              email: user.email,
              title: user.title,
              location: user.location,
              skills: user.skills,
              hourlyRate: user.hourlyRate,
              profilePhoto: user.profilePhoto,
              rating: {
                average: parseFloat(averageRating),
                totalReviews: totalReviews,
                reviews: user.reviews.map(review => ({
                  clientName: review.clientName,
                  rating: review.rating,
                  comment: review.comment,
                  date: review.date
                }))
              }
            } : {
              id: null,
              fullName: 'Unknown User',
              email: project.email,
              title: null,
              location: null,
              skills: [],
              hourlyRate: null,
              profilePhoto: null,
              rating: {
                average: 0,
                totalReviews: 0,
                reviews: []
              }
            }
          };
        } catch (userError) {
          console.error(`Error fetching user data for project ${project._id}:`, userError);

          const projectObj = project.toObject();
          return {
            ...projectObj,
            userProfile: {
              id: null,
              fullName: 'Unknown User',
              email: project.email,
              title: null,
              location: null,
              skills: [],
              hourlyRate: null,
              profilePhoto: null,
              rating: {
                average: 0,
                totalReviews: 0,
                reviews: []
              }
            }
          };
        }
      })
    );

    // Calculate pagination info
    const totalPages = Math.ceil(totalProjects / parseInt(limit));
    const hasNext = parseInt(page) < totalPages;
    const hasPrev = parseInt(page) > 1;

    res.status(200).json({
      success: true,
      message: 'Projects fetched successfully',
      data: enhancedProjects,
      pagination: {
        currentPage: parseInt(page),
        totalPages: totalPages,
        totalProjects: totalProjects,
        projectsPerPage: parseInt(limit),
        hasNext: hasNext,
        hasPrev: hasPrev
      }
    });

  } catch (error) {
    console.error('Error fetching enhanced projects:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch projects',
      error: error.message
    });
  }
});
// Get single project with user profile data
// app.get('/api/projects/:id/with-profile', async (req, res) => {
//   try {
//     const { id } = req.params;

//     // Validate project ID
//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Invalid project ID'
//       });
//     }

//     // Find the project
//     const project = await Project.findById(id);

//     if (!project) {
//       return res.status(404).json({
//         success: false,
//         message: 'Project not found'
//       });
//     }

//     // Find user by email from the project
//     const user = await User.findOne({ email: project.email })
//       .select('fullName profilePhoto reviews email title location skills hourlyRate bio availabilityPerWeek');

//     // Calculate average rating from reviews
//     let averageRating = 0;
//     let totalReviews = 0;

//     if (user && user.reviews && user.reviews.length > 0) {
//       const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
//       totalReviews = user.reviews.length;
//       averageRating = (totalRating / totalReviews).toFixed(1);
//     }

//     // Convert project to object and add user data
//     const projectObj = project.toObject();

//     const enhancedProject = {
//       ...projectObj,
//       userProfile: user ? {
//         id: user._id,
//         fullName: user.fullName,
//         email: user.email,
//         title: user.title,
//         bio: user.bio,
//         location: user.location,
//         skills: user.skills,
//         hourlyRate: user.hourlyRate,
//         availabilityPerWeek: user.availabilityPerWeek,
//         profilePhoto: user.profilePhoto,
//         rating: {
//           average: parseFloat(averageRating),
//           totalReviews: totalReviews,
//           reviews: user.reviews.map(review => ({
//             clientName: review.clientName,
//             clientAvatar: review.clientAvatar,
//             rating: review.rating,
//             comment: review.comment,
//             date: review.date
//           }))
//         }
//       } : {
//         id: null,
//         fullName: 'Unknown User',
//         email: project.email,
//         title: null,
//         bio: null,
//         location: null,
//         skills: [],
//         hourlyRate: null,
//         availabilityPerWeek: null,
//         profilePhoto: null,
//         rating: {
//           average: 0,
//           totalReviews: 0,
//           reviews: []
//         }
//       }
//     };

//     res.status(200).json({
//       success: true,
//       message: 'Project fetched successfully',
//       data: enhancedProject
//     });

//   } catch (error) {
//     console.error('Error fetching project with profile:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch project',
//       error: error.message
//     });
//   }
// });
app.get('/api/projects/with-profiles', async (req, res) => {
  try {
    const projects = await Project.find().sort({ createdAt: -1 });

    if (!projects || projects.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'No projects found',
        data: []
      });
    }

    const enhancedProjects = await Promise.all(
      projects.map(async (project) => {
        try {
          const user = await User.findOne({ email: project.email })
            .select('fullName profilePhoto reviews email title location skills');

          let averageRating = 0;
          let totalReviews = 0;

          if (user && user.reviews && user.reviews.length > 0) {
            const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
            totalReviews = user.reviews.length;
            averageRating = (totalRating / totalReviews).toFixed(1);
          }

          // Fetch bids related to the project with freelancer details
          const bids = await Bid.find({ project: project._id })
            .populate('freelancer', 'fullName email profilePhoto title location skills hourlyRate reviews');

          // Fetch tasks related to the project with assignedTo and assignedBy user details
          const tasks = await Task.find({ project: project._id })
            .populate('assignedTo', 'fullName email profilePhoto')
            .populate('assignedBy', 'fullName email profilePhoto');

          const projectObj = project.toObject();

          return {
            ...projectObj,
            userProfile: user ? {
              id: user._id,
              fullName: user.fullName,
              email: user.email,
              title: user.title,
              location: user.location,
              skills: user.skills,
              profilePhoto: user.profilePhoto,
              rating: {
                average: parseFloat(averageRating),
                totalReviews: totalReviews
              }
            } : {
              id: null,
              fullName: 'Unknown User',
              email: project.email,
              title: null,
              location: null,
              skills: [],
              profilePhoto: null,
              rating: {
                average: 0,
                totalReviews: 0
              }
            },
            bids,
            tasks
          };
        } catch (userError) {
          console.error(`Error fetching user or related data for project ${project._id}:`, userError);

          const projectObj = project.toObject();
          return {
            ...projectObj,
            userProfile: {
              id: null,
              fullName: 'Unknown User',
              email: project.email,
              title: null,
              location: null,
              skills: [],
              profilePhoto: null,
              rating: {
                average: 0,
                totalReviews: 0
              }
            },
            bids: [],
            tasks: []
          };
        }
      })
    );

    res.status(200).json({
      success: true,
      message: 'Projects fetched successfully with bids and tasks',
      data: enhancedProjects,
      count: enhancedProjects.length
    });

  } catch (error) {
    console.error('Error fetching projects with profiles and related bids/tasks:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch projects with related data',
      error: error.message
    });
  }
});

app.post('/api/projects/myBids', async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ message: "User ID is required." });
    }

    // Find all bids made by this freelancer
    const bids = await Bid.find({ freelancer: userId })
      .populate({
        path: 'project',
        select: 'title description budget_from budget_to email'
      })
      .sort({ createdAt: -1 });

    if (!bids.length) {
      return res.status(404).json({ message: "No bids found for this user." });
    }

    // Fetch client names using project.email
    const enrichedBids = await Promise.all(
      bids.map(async (bid) => {
        // Fix: Use 'fullName' instead of 'name' as per your User schema
        const client = await User.findOne({ email: bid.project.email }, 'fullName email');

        return {
          ...bid.toObject(),
          project: {
            ...bid.project.toObject(),
            clientName: client ? client.fullName : 'Unknown Client', // Use fullName
            clientEmail: bid.project.email
          }
        };
      })
    );

    return res.status(200).json({
      message: "Bids fetched successfully",
      bids: enrichedBids
    });

  } catch (error) {
    console.error("🔥 Error fetching bids:", error.message);
    return res.status(500).json({ message: "Server error while fetching bids" });
  }
});
app.post('/api/bookmarks/toggle', async (req, res) => {
  try {
    const { projectId, userId, userEmail } = req.body;

    if (!projectId || !userId || !userEmail) {
      return res.status(400).json({
        success: false,
        message: "Project ID, User ID, and User Email are required."
      });
    }

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found."
      });
    }

    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    // Check if bookmark already exists
    const existingBookmark = await Bookmark.findOne({
      user: userId,
      project: projectId
    });

    if (existingBookmark) {
      // Remove bookmark if it exists
      await Bookmark.findByIdAndDelete(existingBookmark._id);

      return res.status(200).json({
        success: true,
        message: "Project removed from bookmarks",
        action: "removed",
        bookmarked: false
      });
    } else {
      // Create new bookmark
      const newBookmark = new Bookmark({
        user: userId,
        userEmail: userEmail,
        project: projectId,
        projectId: project.project_id || projectId
      });

      await newBookmark.save();

      return res.status(201).json({
        success: true,
        message: "Project added to bookmarks",
        action: "added",
        bookmarked: true,
        bookmark: newBookmark
      });
    }

  } catch (error) {
    console.error("🔥 Error toggling bookmark:", error.message);

    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "Project is already bookmarked."
      });
    }

    return res.status(500).json({
      success: false,
      message: "Server error while managing bookmark",
      error: error.message
    });
  }
});
// Get User's Bookmarks with Project Details
app.get('/api/bookmarks/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "User ID is required."
      });
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get total count
    const totalBookmarks = await Bookmark.countDocuments({ user: userId });

    // Fetch bookmarks with project details
    const bookmarks = await Bookmark.find({ user: userId })
      .populate({
        path: 'project',
        select: 'title description budget_from budget_to project_type project_duration req_skills email createdAt'
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    if (!bookmarks.length) {
      return res.status(200).json({
        success: true,
        message: "No bookmarks found",
        data: [],
        pagination: {
          currentPage: parseInt(page),
          totalPages: 0,
          totalBookmarks: 0,
          hasNext: false,
          hasPrev: false
        }
      });
    }

    // Enhance bookmarks with client information
    const enhancedBookmarks = await Promise.all(
      bookmarks.map(async (bookmark) => {
        try {
          // Get client details from project email
          const client = await User.findOne({ email: bookmark.project.email })
            .select('fullName email profilePhoto title location');

          return {
            id: bookmark._id,
            bookmarkedAt: bookmark.createdAt,
            project: {
              ...bookmark.project.toObject(),
              client: client ? {
                name: client.fullName,
                email: client.email,
                profilePhoto: client.profilePhoto,
                title: client.title,
                location: client.location
              } : {
                name: 'Unknown Client',
                email: bookmark.project.email,
                profilePhoto: null,
                title: null,
                location: null
              }
            }
          };
        } catch (error) {
          console.error(`Error enhancing bookmark ${bookmark._id}:`, error);
          return {
            id: bookmark._id,
            bookmarkedAt: bookmark.createdAt,
            project: {
              ...bookmark.project.toObject(),
              client: {
                name: 'Unknown Client',
                email: bookmark.project.email,
                profilePhoto: null,
                title: null,
                location: null
              }
            }
          };
        }
      })
    );

    // Calculate pagination info
    const totalPages = Math.ceil(totalBookmarks / parseInt(limit));
    const hasNext = parseInt(page) < totalPages;
    const hasPrev = parseInt(page) > 1;

    return res.status(200).json({
      success: true,
      message: "Bookmarks fetched successfully",
      data: enhancedBookmarks,
      pagination: {
        currentPage: parseInt(page),
        totalPages: totalPages,
        totalBookmarks: totalBookmarks,
        bookmarksPerPage: parseInt(limit),
        hasNext: hasNext,
        hasPrev: hasPrev
      }
    });

  } catch (error) {
    console.error("🔥 Error fetching bookmarks:", error.message);
    return res.status(500).json({
      success: false,
      message: "Server error while fetching bookmarks",
      error: error.message
    });
  }
});
// Check if Project is Bookmarked by User
app.get('/api/bookmarks/check/:userId/:projectId', async (req, res) => {
  try {
    const { userId, projectId } = req.params;

    if (!userId || !projectId) {
      return res.status(400).json({
        success: false,
        message: "User ID and Project ID are required."
      });
    }

    const bookmark = await Bookmark.findOne({
      user: userId,
      project: projectId
    });

    return res.status(200).json({
      success: true,
      isBookmarked: !!bookmark,
      bookmarkId: bookmark ? bookmark._id : null
    });

  } catch (error) {
    console.error("🔥 Error checking bookmark:", error.message);
    return res.status(500).json({
      success: false,
      message: "Server error while checking bookmark",
      error: error.message
    });
  }
});
// Remove Specific Bookmark
app.delete('/api/bookmarks/:bookmarkId', async (req, res) => {
  try {
    const { bookmarkId } = req.params;

    if (!bookmarkId) {
      return res.status(400).json({
        success: false,
        message: "Bookmark ID is required."
      });
    }

    const bookmark = await Bookmark.findByIdAndDelete(bookmarkId);

    if (!bookmark) {
      return res.status(404).json({
        success: false,
        message: "Bookmark not found."
      });
    }

    return res.status(200).json({
      success: true,
      message: "Bookmark removed successfully"
    });

  } catch (error) {
    console.error("🔥 Error removing bookmark:", error.message);
    return res.status(500).json({
      success: false,
      message: "Server error while removing bookmark",
      error: error.message
    });
  }
});
app.post('/api/projects/place_bid', async (req, res) => {
  try {
    const { projectId, freelancerId, price, estimatedTime, description } = req.body;

    console.log("➡️ Incoming request body:", req.body);

    if (!projectId || !freelancerId || !price || !estimatedTime || !description) {
      console.log("❌ Validation failed: Missing fields");
      return res.status(400).json({ message: "All fields are required." });
    }

    // Check if project exists
    const project = await Project.findById(projectId);
    if (!project) {
      console.log(`❌ Project not found for ID: ${projectId}`);
      return res.status(404).json({ message: "Project not found." });
    }

    // Check if freelancer exists
    const freelancer = await User.findById(freelancerId);
    if (!freelancer) {
      console.log(`❌ Freelancer not found for ID: ${freelancerId}`);
      return res.status(404).json({ message: "Freelancer not found." });
    }

    // Check if freelancer has already bid on this project
    const existingBid = await Bid.findOne({
      project: projectId,
      freelancer: freelancerId
    });

    if (existingBid) {
      return res.status(409).json({
        message: "You have already placed a bid on this project."
      });
    }

    // Create and save bid
    const newBid = new Bid({
      project: project._id,
      freelancer: freelancer._id,
      amount: price,
      deliveryTime: estimatedTime,
      coverLetter: description
    });

    await newBid.save();

    // 🎯 AUTO-REMOVE BOOKMARK WHEN BID IS PLACED
    try {
      const removedBookmark = await Bookmark.findOneAndDelete({
        user: freelancerId,
        project: projectId
      });

      if (removedBookmark) {
        console.log(`✅ Automatically removed bookmark for user ${freelancerId} on project ${projectId}`);
      }
    } catch (bookmarkError) {
      console.error("⚠️ Error removing bookmark after bid placement:", bookmarkError);
      // Don't fail the bid placement if bookmark removal fails
    }

    return res.status(201).json({
      message: "Bid submitted successfully",
      bid: newBid,
      bookmarkRemoved: true // Indicate that bookmark was automatically removed
    });

  } catch (error) {
    console.error("🔥 Error placing bid:", error.message);
    console.error(error.stack);
    return res.status(500).json({ message: "Server error while placing bid" });
  }
});
app.get('/api/projects/my-projects/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 10, status = 'all' } = req.query;

    // Verify user exists and is the same as authenticated user (or admin)
    // if (req.user.id !== userId ) {
    if (String(req.user.id) !== String(userId)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access these projects'
      });
    }

    // Get user email to find projects
    const user = await User.findById(userId).select('email fullName');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter for projects by user email
    const projectFilter = { email: user.email };

    // Get total count
    const totalProjects = await Project.countDocuments(projectFilter);

    // Fetch user's projects
    const projects = await Project.find(projectFilter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    if (!projects.length) {
      return res.status(200).json({
        success: true,
        message: 'No projects found',
        data: [],
        pagination: {
          currentPage: parseInt(page),
          totalPages: 0,
          totalProjects: 0,
          hasNext: false,
          hasPrev: false
        }
      });
    }

    // Enhance each project with bid information
    const enhancedProjects = await Promise.all(
      projects.map(async (project) => {
        try {
          // Get all bids for this project
          const bids = await Bid.find({ project: project._id })
            .populate({
              path: 'freelancer',
              select: 'fullName email profilePhoto title location skills hourlyRate reviews'
            })
            .sort({ createdAt: -1 });

          // Enhance bids with freelancer ratings
          const enhancedBids = bids.map(bid => {
            const freelancer = bid.freelancer;
            let averageRating = 0;
            let totalReviews = 0;

            if (freelancer && freelancer.reviews && freelancer.reviews.length > 0) {
              const totalRating = freelancer.reviews.reduce((sum, review) => sum + review.rating, 0);
              totalReviews = freelancer.reviews.length;
              averageRating = (totalRating / totalReviews).toFixed(1);
            }

            return {
              id: bid._id,
              amount: bid.amount,
              deliveryTime: bid.deliveryTime,
              coverLetter: bid.coverLetter,
              status: bid.status,
              createdAt: bid.createdAt,
              freelancer: {
                id: freelancer._id,
                fullName: freelancer.fullName,
                email: freelancer.email,
                profilePhoto: freelancer.profilePhoto,
                title: freelancer.title,
                location: freelancer.location,
                skills: freelancer.skills,
                hourlyRate: freelancer.hourlyRate,
                rating: {
                  average: parseFloat(averageRating),
                  totalReviews: totalReviews
                }
              }
            };
          });

          // Filter bids by status if specified
          let filteredBids = enhancedBids;
          if (status !== 'all') {
            filteredBids = enhancedBids.filter(bid => bid.status === status);
          }

          // Calculate bid statistics
          const bidStats = {
            total: enhancedBids.length,
            pending: enhancedBids.filter(bid => bid.status === 'pending').length,
            accepted: enhancedBids.filter(bid => bid.status === 'accepted').length,
            rejected: enhancedBids.filter(bid => bid.status === 'rejected').length,
            averageBid: enhancedBids.length > 0
              ? (enhancedBids.reduce((sum, bid) => sum + bid.amount, 0) / enhancedBids.length).toFixed(2)
              : 0,
            lowestBid: enhancedBids.length > 0
              ? Math.min(...enhancedBids.map(bid => bid.amount))
              : 0,
            highestBid: enhancedBids.length > 0
              ? Math.max(...enhancedBids.map(bid => bid.amount))
              : 0
          };

          return {
            ...project.toObject(),
            bids: filteredBids,
            bidStatistics: bidStats,
            canStartChat: enhancedBids.some(bid => bid.status === 'accepted') || enhancedBids.length > 0
          };

        } catch (error) {
          console.error(`Error enhancing project ${project._id}:`, error);
          return {
            ...project.toObject(),
            bids: [],
            bidStatistics: {
              total: 0, pending: 0, accepted: 0, rejected: 0,
              averageBid: 0, lowestBid: 0, highestBid: 0
            },
            canStartChat: false
          };
        }
      })
    );

    // Calculate pagination info
    const totalPages = Math.ceil(totalProjects / parseInt(limit));
    const hasNext = parseInt(page) < totalPages;
    const hasPrev = parseInt(page) > 1;

    res.status(200).json({
      success: true,
      message: 'Projects fetched successfully',
      data: enhancedProjects,
      pagination: {
        currentPage: parseInt(page),
        totalPages: totalPages,
        totalProjects: totalProjects,
        projectsPerPage: parseInt(limit),
        hasNext: hasNext,
        hasPrev: hasPrev
      }
    });

  } catch (error) {
    console.error('Error fetching user projects:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch projects',
      error: error.message
    });
  }
});
app.put('/api/bids/:bidId/status', async (req, res) => {
  try {
    const { bidId } = req.params;
    const { status, message } = req.body;

    console.log('Received bid update request:', { bidId, status, message });

    if (!['accepted', 'rejected'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status must be either "accepted" or "rejected"'
      });
    }

    // Find the bid and populate project data
    const bid = await Bid.findById(bidId).populate('project');
    if (!bid) {
      return res.status(404).json({
        success: false,
        message: 'Bid not found'
      });
    }

    console.log('Found bid:', bid);

    // Update bid status
    bid.status = status;
    await bid.save();

    console.log('Bid status updated to:', status);

    // If bid is accepted, reject all other pending bids for the same project
    if (status === 'accepted') {
      const rejectedBids = await Bid.updateMany(
        {
          project: bid.project._id,
          _id: { $ne: bid._id },
          status: 'pending'
        },
        { status: 'rejected' }
      );

      console.log('Rejected other bids:', rejectedBids);

      // For conversation creation, you'll need to get the project owner
      const projectOwner = await User.findOne({ email: bid.project.email });

      if (projectOwner) {
        // Create a conversation between project owner and freelancer
        let conversation = await Conversation.findOne({
          participants: { $all: [projectOwner._id, bid.freelancer] },
          project: bid.project._id
        });

        if (!conversation) {
          conversation = await Conversation.create({
            participants: [projectOwner._id, bid.freelancer],
            project: bid.project._id
          });
        }

        // Send initial message if provided
        if (message && message.trim()) {
          const initialMessage = await Message.create({
            conversation: conversation._id,
            sender: projectOwner._id,
            content: message
          });

          conversation.lastMessage = initialMessage._id;
          await conversation.save();
        }
      }
    }

    // Send proper response with data
    return res.status(200).json({
      success: true,
      message: `Bid ${status} successfully`,
      data: {
        bid: {
          id: bid._id,
          status: bid.status,
          amount: bid.amount,
          deliveryTime: bid.deliveryTime,
          coverLetter: bid.coverLetter,
          freelancer: bid.freelancer
        }
      }
    });

  } catch (error) {
    console.error('Error updating bid status:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to update bid status',
      error: error.message
    });
  }
});
app.get('/api/conversations', verifyToken, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const conversations = await Conversation.find({
      participants: req.user.id
    })
      .populate({
        path: 'participants',
        select: 'fullName email profilePhoto title',
        match: { _id: { $ne: req.user.id } } // Exclude current user
      })
      .populate({
        path: 'project',
        select: 'title project_id budget_from budget_to'
      })
      .populate({
        path: 'lastMessage',
        select: 'content createdAt sender read'
      })
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Count unread messages for each conversation
    const enhancedConversations = await Promise.all(
      conversations.map(async (conv) => {
        const unreadCount = await Message.countDocuments({
          conversation: conv._id,
          sender: { $ne: req.user.id },
          read: false
        });

        return {
          id: conv._id,
          project: conv.project,
          participant: conv.participants[0], // The other user
          lastMessage: conv.lastMessage,
          unreadCount: unreadCount,
          createdAt: conv.createdAt,
          updatedAt: conv.updatedAt
        };
      })
    );

    const totalConversations = await Conversation.countDocuments({
      participants: req.user.id
    });

    res.status(200).json({
      success: true,
      data: enhancedConversations,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalConversations / parseInt(limit)),
        totalConversations: totalConversations,
        hasNext: parseInt(page) < Math.ceil(totalConversations / parseInt(limit)),
        hasPrev: parseInt(page) > 1
      }
    });

  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch conversations',
      error: error.message
    });
  }
});
app.get('/api/conversations/:conversationId/messages', verifyToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Verify user is part of the conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user.id
    });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found or access denied'
      });
    }

    const messages = await Message.find({ conversation: conversationId })
      .populate({
        path: 'sender',
        select: 'fullName profilePhoto'
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Mark messages as read for the current user
    await Message.updateMany(
      {
        conversation: conversationId,
        sender: { $ne: req.user.id },
        read: false
      },
      { read: true }
    );

    const totalMessages = await Message.countDocuments({ conversation: conversationId });

    res.status(200).json({
      success: true,
      data: messages.reverse(), // Reverse to show oldest first
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalMessages / parseInt(limit)),
        totalMessages: totalMessages,
        hasNext: parseInt(page) < Math.ceil(totalMessages / parseInt(limit)),
        hasPrev: parseInt(page) > 1
      }
    });

  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages',
      error: error.message
    });
  }
});
app.post('/api/conversations/:conversationId/messages', verifyToken, upload.single('attachment'), async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { content } = req.body;

    if (!content && !req.file) {
      return res.status(400).json({
        success: false,
        message: 'Message content or attachment is required'
      });
    }

    // Verify user is part of the conversation
    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user.id
    });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found or access denied'
      });
    }

    // Create message
    const messageData = {
      conversation: conversationId,
      sender: req.user.id,
      content: content || ''
    };

    if (req.file) {
      messageData.attachment = `/uploads/${req.file.filename}`;
    }

    const message = await Message.create(messageData);

    // Update conversation's last message
    conversation.lastMessage = message._id;
    conversation.updatedAt = new Date();
    await conversation.save();

    // Populate sender info for response
    await message.populate({
      path: 'sender',
      select: 'fullName profilePhoto'
    });

    // Emit socket event to other participants
    const otherParticipants = conversation.participants.filter(
      p => p.toString() !== req.user.id
    );

    otherParticipants.forEach(participantId => {
      io.to(`user_${participantId}`).emit('new_message', {
        conversationId: conversationId,
        message: message
      });
    });

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: message
    });

  } catch (error) {
    console.error('Error sending message:', error);

    // Delete uploaded file if there was an error
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (deleteErr) {
        console.error('Error deleting uploaded file:', deleteErr);
      }
    }

    res.status(500).json({
      success: false,
      message: 'Failed to send message',
      error: error.message
    });
  }
});
app.post('/api/conversations/create', verifyToken, async (req, res) => {
  try {
    const { participantId, projectId, initialMessage } = req.body;

    if (!participantId || !projectId) {
      return res.status(400).json({
        success: false,
        message: 'Participant ID and Project ID are required'
      });
    }

    // Verify project exists
    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({
        success: false,
        message: 'Project not found'
      });
    }

    // Verify participant exists
    const participant = await User.findById(participantId);
    if (!participant) {
      return res.status(404).json({
        success: false,
        message: 'Participant not found'
      });
    }

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, participantId] },
      project: projectId
    });

    if (!conversation) {
      // Create new conversation
      conversation = await Conversation.create({
        participants: [req.user.id, participantId],
        project: projectId
      });
    }

    // Send initial message if provided
    if (initialMessage) {
      const message = await Message.create({
        conversation: conversation._id,
        sender: req.user.id,
        content: initialMessage
      });

      conversation.lastMessage = message._id;
      await conversation.save();

      // Emit socket event
      io.to(`user_${participantId}`).emit('new_message', {
        conversationId: conversation._id,
        message: message
      });
    }

    // Populate conversation data for response
    await conversation.populate([
      {
        path: 'participants',
        select: 'fullName email profilePhoto title'
      },
      {
        path: 'project',
        select: 'title project_id budget_from budget_to'
      },
      {
        path: 'lastMessage',
        select: 'content createdAt sender'
      }
    ]);

    res.status(201).json({
      success: true,
      message: 'Conversation created successfully',
      data: conversation
    });

  } catch (error) {
    console.error('Error creating conversation:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create conversation',
      error: error.message
    });
  }
});
app.get('/api/conversations/:conversationId', verifyToken, async (req, res) => {
  try {
    const { conversationId } = req.params;

    const conversation = await Conversation.findOne({
      _id: conversationId,
      participants: req.user.id
    })
      .populate({
        path: 'participants',
        select: 'fullName email profilePhoto title'
      })
      .populate({
        path: 'project',
        select: 'title project_id budget_from budget_to description req_skills'
      });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: 'Conversation not found or access denied'
      });
    }

    // Get unread message count
    const unreadCount = await Message.countDocuments({
      conversation: conversationId,
      sender: { $ne: req.user.id },
      read: false
    });

    res.status(200).json({
      success: true,
      data: {
        ...conversation.toObject(),
        unreadCount
      }
    });

  } catch (error) {
    console.error('Error fetching conversation details:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch conversation details',
      error: error.message
    });
  }
});
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Join user to their personal room
  socket.on('join_user_room', (userId) => {
    socket.join(`user_${userId}`);
    console.log(`User ${userId} joined their personal room`);
  });

  // Join conversation room
  socket.on('join_conversation', (conversationId) => {
    socket.join(`conversation_${conversationId}`);
    console.log(`User joined conversation: ${conversationId}`);
  });

  // Leave conversation room
  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conversation_${conversationId}`);
    console.log(`User left conversation: ${conversationId}`);
  });

  // Handle typing indicators
  socket.on('typing_start', (data) => {
    socket.to(`conversation_${data.conversationId}`).emit('user_typing', {
      userId: data.userId,
      userName: data.userName
    });
  });

  socket.on('typing_stop', (data) => {
    socket.to(`conversation_${data.conversationId}`).emit('user_stopped_typing', {
      userId: data.userId
    });
  });

  // Handle message read receipts
  socket.on('message_read', async (data) => {
    try {
      await Message.findByIdAndUpdate(data.messageId, { read: true });
      socket.to(`conversation_${data.conversationId}`).emit('message_read_receipt', {
        messageId: data.messageId,
        readBy: data.userId
      });
    } catch (error) {
      console.error('Error updating message read status:', error);
    }
  });

  // Handle online status
  socket.on('user_online', (userId) => {
    socket.broadcast.emit('user_status_change', {
      userId: userId,
      status: 'online'
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    // You could implement user offline status here
  });
  // Join task room for real-time updates
  socket.on('join_task', (taskId) => {
    socket.join(`task_${taskId}`);
    console.log(`User joined task: ${taskId}`);
  });

  // Leave task room
  socket.on('leave_task', (taskId) => {
    socket.leave(`task_${taskId}`);
    console.log(`User left task: ${taskId}`);
  });

  // Handle task updates from clients
  socket.on('task_update', async (data) => {
    try {
      const { taskId, updates } = data;

      // Verify user has permission to update the task
      const task = await Task.findById(taskId);
      if (!task) return;

      const hasAccess = (
        task.assignedTo.toString() === socket.userId ||
        task.assignedBy.toString() === socket.userId
      );

      if (!hasAccess) return;

      // Broadcast update to other users in the task room
      socket.to(`task_${taskId}`).emit('task_updated', {
        taskId,
        updates,
        updatedBy: socket.userId
      });
    } catch (error) {
      console.error('Error handling task update:', error);
    }
  });
});
app.get('/api/chat/stats', async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    // ✅ Convert userId to ObjectId
    const objectId = new mongoose.Types.ObjectId(userId);

    const conversationIds = (await Conversation.find({ participants: objectId }).select('_id'))
      .map(c => c._id);

    const [totalConversations, unreadMessages, activeChats] = await Promise.all([
      Conversation.countDocuments({ participants: objectId }),
      Message.countDocuments({
        conversation: { $in: conversationIds },
        sender: { $ne: objectId },
        read: false
      }),
      Conversation.countDocuments({
        participants: objectId,
        updatedAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      })
    ]);

    res.status(200).json({
      success: true,
      data: {
        totalConversations,
        unreadMessages,
        activeChats,
        lastWeekActivity: activeChats
      }
    });

  } catch (error) {
    console.error('Error fetching chat stats:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch chat statistics',
      error: error.message
    });
  }
});
app.get('/api/conversations/search', verifyToken, async (req, res) => {
  try {
    const { query, limit = 10 } = req.query;

    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    const conversations = await Conversation.find({
      participants: req.user.id
    })
      .populate({
        path: 'participants',
        select: 'fullName email profilePhoto title',
        match: {
          $and: [
            { _id: { $ne: req.user.id } },
            {
              $or: [
                { fullName: { $regex: query, $options: 'i' } },
                { email: { $regex: query, $options: 'i' } },
                { title: { $regex: query, $options: 'i' } }
              ]
            }
          ]
        }
      })
      .populate({
        path: 'project',
        select: 'title project_id',
        match: {
          title: { $regex: query, $options: 'i' }
        }
      })
      .limit(parseInt(limit));

    // Filter out conversations where no matches were found
    const filteredConversations = conversations.filter(conv =>
      (conv.participants && conv.participants.length > 0) ||
      (conv.project && conv.project.title)
    );

    res.status(200).json({
      success: true,
      data: filteredConversations,
      count: filteredConversations.length
    });

  } catch (error) {
    console.error('Error searching conversations:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search conversations',
      error: error.message
    });
  }
});
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};
app.get('/api/dashboard/overview', authenticateToken, async (req, res) => {
  try {
    // Find user by ID from token
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // ✅ Fetch bookmarks for this user
    const bookmarks = await Bookmark.find({ user: req.user.id })
      .populate('project', 'title project_id') // project info
      .sort({ createdAt: -1 })
      .limit(5);

    // ✅ Fetch bids for this user (as freelancer)
    const bids = await Bid.find({ freelancer: user._id })
      .populate('project', 'title') // get project title
      .sort({ createdAt: -1 })
      .limit(5);

    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        role: user.role || user.userType
      },
      activities: [],  // placeholder until Activity model is ready
      bookmarks: {
        count: await Bookmark.countDocuments({ user: req.user.id }),
        recent: bookmarks.map(b => ({
          id: b._id,
          projectId: b.project ? b.project._id : null,
          projectTitle: b.project ? b.project.title : null,
          userEmail: b.userEmail,
          createdAt: b.createdAt
        }))
      },
      bids: {
        count: await Bid.countDocuments({ freelancer: user._id }),
        recent: bids.map(b => ({
          id: b._id,
          projectId: b.project ? b.project._id : null,
          projectTitle: b.project ? b.project.title : null,
          amount: b.amount,
          deliveryTime: b.deliveryTime,
          status: b.status,
          createdAt: b.createdAt
        }))
      }
    });

  } catch (error) {
    console.error('Overview API error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});
app.get('/api/dashboard/analytics', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Ensure userId is converted to ObjectId properly
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid user ID'
      });
    }

    const user = await User.findById(userId).select('role email');

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    let analytics = {};

    if (user.role === 'freelancer') {
      // Freelancer-specific analytics
      analytics = await getFreelancerAnalytics(new mongoose.Types.ObjectId(userId));
    } else if (user.role === 'client') {
      // Client-specific analytics
      analytics = await getClientAnalytics(user.email);
    } else {
      // Admin or other roles (basic analytics)
      analytics = await getBasicAnalytics(new mongoose.Types.ObjectId(userId));
    }

    res.status(200).json({
      success: true,
      data: analytics
    });

  } catch (error) {
    console.error('Dashboard analytics error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard analytics',
      error: error.message
    });
  }
});
async function getFreelancerAnalytics(userId) {
  // Get all bids by this freelancer
  const bids = await Bid.find({ freelancer: userId })
    .populate('project', 'title budget_from budget_to project_type')
    .sort({ createdAt: -1 });

  // Get accepted bids
  const acceptedBids = bids.filter(bid => bid.status === 'accepted');

  // Get user profile data
  const user = await User.findById(userId)
    .select('skills hourlyRate profileCompleteness reviews createdAt')
    .lean();

  // Get conversations count
  const conversationCount = await Conversation.countDocuments({
    participants: userId
  });

  // Get unread messages count
  const unreadMessages = await Message.countDocuments({
    conversation: { $in: await Conversation.find({ participants: userId }).select('_id') },
    sender: { $ne: userId },
    read: false
  });

  // Calculate earnings data
  const earningsData = calculateEarningsData(acceptedBids);

  // Calculate bid success rate
  const bidSuccessRate = bids.length > 0
    ? Math.round((acceptedBids.length / bids.length) * 100)
    : 0;

  // Calculate skills distribution
  const skillsDistribution = calculateSkillsDistribution(bids);

  // Calculate project type distribution
  const projectTypeDistribution = calculateProjectTypeDistribution(bids);

  return {
    role: 'freelancer',
    overview: {
      totalBids: bids.length,
      acceptedBids: acceptedBids.length,
      bidSuccessRate,
      totalEarnings: earningsData.totalEarnings,
      averageEarningsPerProject: earningsData.averageEarnings,
      profileCompleteness: user.profileCompleteness || 0,
      rating: calculateAverageRating(user.reviews),
      activeConversations: conversationCount,
      unreadMessages
    },
    earnings: earningsData,
    activity: {
      bidsLast30Days: await getBidActivity(userId, 30),
      earningsLast12Months: await getEarningsOverTime(userId, 12)
    },
    skills: {
      topSkills: user.skills?.slice(0, 5) || [],
      skillsDistribution,
      mostProfitableSkills: getMostProfitableSkills(acceptedBids, user.skills || [])
    },
    projects: {
      projectTypeDistribution,
      averageProjectBudget: calculateAverageProjectBudget(bids),
      completionRate: calculateProjectCompletionRate(userId)
    },
    performance: {
      responseTime: await calculateAverageResponseTime(userId),
      clientSatisfaction: calculateClientSatisfaction(user.reviews),
      profileViews: 0 // Would need tracking implementation
    }
  };
}
async function getClientAnalytics(userEmail) {
  // Get all projects by this client
  const projects = await Project.find({ email: userEmail })
    .sort({ createdAt: -1 });

  // Get project IDs for queries
  const projectIds = projects.map(p => p._id);

  // Get all bids for client's projects
  const bids = await Bid.find({ project: { $in: projectIds } })
    .populate('freelancer', 'fullName hourlyRate skills')
    .populate('project', 'title budget_from budget_to');

  // Get accepted bids
  const acceptedBids = bids.filter(bid => bid.status === 'accepted');

  // Calculate spending data
  const spendingData = calculateSpendingData(acceptedBids);

  // Get conversations count
  const conversationCount = await Conversation.countDocuments({
    participants: { $in: await User.find({ email: userEmail }).select('_id') }
  });

  // Get unread messages count
  const unreadMessages = await Message.countDocuments({
    conversation: {
      $in: await Conversation.find({
        participants: { $in: await User.find({ email: userEmail }).select('_id') }
      }).select('_id')
    },
    sender: { $nin: await User.find({ email: userEmail }).select('_id') },
    read: false
  });

  // Calculate freelancer stats
  const freelancerStats = calculateFreelancerStats(bids);

  return {
    role: 'client',
    overview: {
      totalProjects: projects.length,
      activeProjects: projects.length - acceptedBids.length, // Projects without accepted bids
      completedProjects: acceptedBids.length,
      totalSpent: spendingData.totalSpent,
      averageProjectBudget: calculateAverageClientProjectBudget(projects),
      averageBidsPerProject: projects.length > 0 ? Math.round(bids.length / projects.length) : 0,
      activeConversations: conversationCount,
      unreadMessages
    },
    spending: spendingData,
    activity: {
      projectsLast30Days: await getProjectActivity(userEmail, 30),
      spendingLast12Months: await getSpendingOverTime(userEmail, 12)
    },
    freelancers: {
      topFreelancers: getTopFreelancers(bids),
      freelancerStats,
      hiringPatterns: analyzeHiringPatterns(acceptedBids)
    },
    projects: {
      projectTypeDistribution: calculateClientProjectTypeDistribution(projects),
      budgetDistribution: calculateBudgetDistribution(projects),
      averageTimeToHire: calculateAverageTimeToHire(projects, bids)
    },
    performance: {
      projectCompletionRate: calculateClientProjectCompletionRate(projects, acceptedBids),
      freelancerSatisfaction: calculateFreelancerSatisfaction(bids),
      averageResponseTime: calculateAverageClientResponseTime(projects, bids)
    }
  };
}
async function getBasicAnalytics(userId) {
  // Basic analytics for users with other roles
  const user = await User.findById(userId)
    .select('profileCompleteness reviews createdAt')
    .lean();

  return {
    role: 'user',
    overview: {
      profileCompleteness: user.profileCompleteness || 0,
      rating: calculateAverageRating(user.reviews),
      memberSince: user.createdAt
    }
  };
}
function calculateEarningsData(acceptedBids) {
  const totalEarnings = acceptedBids.reduce((sum, bid) => sum + bid.amount, 0);
  const averageEarnings = acceptedBids.length > 0
    ? Math.round(totalEarnings / acceptedBids.length)
    : 0;

  // Calculate earnings by month for the last 12 months
  const monthlyEarnings = {};
  const currentDate = new Date();

  for (let i = 11; i >= 0; i--) {
    const date = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
    const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
    monthlyEarnings[monthKey] = 0;
  }

  acceptedBids.forEach(bid => {
    const monthKey = bid.createdAt.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
    if (monthlyEarnings.hasOwnProperty(monthKey)) {
      monthlyEarnings[monthKey] += bid.amount;
    }
  });

  return {
    totalEarnings,
    averageEarnings,
    monthlyEarnings: Object.entries(monthlyEarnings).map(([month, amount]) => ({ month, amount })),
    highestPayingProject: acceptedBids.length > 0
      ? acceptedBids.reduce((max, bid) => bid.amount > max.amount ? bid : max, acceptedBids[0])
      : null
  };
}
function calculateSpendingData(acceptedBids) {
  const totalSpent = acceptedBids.reduce((sum, bid) => sum + bid.amount, 0);
  const averageSpending = acceptedBids.length > 0
    ? Math.round(totalSpent / acceptedBids.length)
    : 0;

  // Calculate spending by month for the last 12 months
  const monthlySpending = {};
  const currentDate = new Date();

  for (let i = 11; i >= 0; i--) {
    const date = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
    const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
    monthlySpending[monthKey] = 0;
  }

  acceptedBids.forEach(bid => {
    const monthKey = bid.createdAt.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
    if (monthlySpending.hasOwnProperty(monthKey)) {
      monthlySpending[monthKey] += bid.amount;
    }
  });

  return {
    totalSpent,
    averageSpending,
    monthlySpending: Object.entries(monthlySpending).map(([month, amount]) => ({ month, amount })),
    highestPaidProject: acceptedBids.length > 0
      ? acceptedBids.reduce((max, bid) => bid.amount > max.amount ? bid : max, acceptedBids[0])
      : null
  };
}
function calculateAverageRating(reviews) {
  if (!reviews || reviews.length === 0) return 0;
  const total = reviews.reduce((sum, review) => sum + review.rating, 0);
  return parseFloat((total / reviews.length).toFixed(1));
}
function calculateSkillsDistribution(bids) {
  const skillsMap = {};

  bids.forEach(bid => {
    if (bid.project && bid.project.req_skills) {
      bid.project.req_skills.forEach(skill => {
        skillsMap[skill] = (skillsMap[skill] || 0) + 1;
      });
    }
  });

  return Object.entries(skillsMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([skill, count]) => ({ skill, count }));
}
function calculateProjectTypeDistribution(bids) {
  const typeMap = {};

  bids.forEach(bid => {
    if (bid.project && bid.project.project_type) {
      const type = bid.project.project_type;
      typeMap[type] = (typeMap[type] || 0) + 1;
    }
  });

  return Object.entries(typeMap)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({ type, count }));
}
function calculateAverageProjectBudget(bids) {
  const projectsWithBudget = bids.filter(bid => bid.project && bid.project.budget_from && bid.project.budget_to);
  if (projectsWithBudget.length === 0) return 0;

  const total = projectsWithBudget.reduce((sum, bid) => {
    return sum + ((bid.project.budget_from + bid.project.budget_to) / 2);
  }, 0);

  return Math.round(total / projectsWithBudget.length);
}
async function calculateProjectCompletionRate(userId) {
  const acceptedBids = await Bid.countDocuments({
    freelancer: userId,
    status: 'accepted'
  });

  const completedBids = await Bid.countDocuments({
    freelancer: userId,
    status: 'completed' // Would need to add this status
  });

  if (acceptedBids === 0) return 0;
  return Math.round((completedBids / acceptedBids) * 100);
}
async function calculateAverageResponseTime(userId) {
  // This would need message timestamps and project posting times
  // Simplified version - average time between project posting and bid submission
  const bids = await Bid.find({ freelancer: userId })
    .populate('project', 'createdAt')
    .sort({ createdAt: -1 })
    .limit(50);

  if (bids.length === 0) return 'N/A';

  const totalResponseTime = bids.reduce((sum, bid) => {
    if (bid.project && bid.project.createdAt && bid.createdAt) {
      return sum + (bid.createdAt - bid.project.createdAt);
    }
    return sum;
  }, 0);

  const averageMs = totalResponseTime / bids.length;
  return formatDuration(averageMs);
}
function calculateClientSatisfaction(reviews) {
  if (!reviews || reviews.length === 0) return 0;
  const positiveReviews = reviews.filter(r => r.rating >= 4).length;
  return Math.round((positiveReviews / reviews.length) * 100);
}
function getMostProfitableSkills(acceptedBids, userSkills) {
  const skillEarnings = {};

  acceptedBids.forEach(bid => {
    if (bid.project && bid.project.req_skills) {
      bid.project.req_skills.forEach(skill => {
        if (userSkills.includes(skill)) {
          skillEarnings[skill] = (skillEarnings[skill] || 0) + bid.amount;
        }
      });
    }
  });

  return Object.entries(skillEarnings)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([skill, earnings]) => ({ skill, earnings }));
}
async function getBidActivity(userId, days) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const bids = await Bid.aggregate([
    {
      $match: {
        freelancer: new mongoose.Types.ObjectId(userId), // Add 'new' keyword here
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
        count: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  return bids;
}
async function getEarningsOverTime(userId, months) {
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - months);

  const earnings = await Bid.aggregate([
    {
      $match: {
        freelancer: new mongoose.Types.ObjectId(userId), // Add 'new' keyword here
        status: 'accepted',
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
        amount: { $sum: "$amount" }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  return earnings;
}
function calculateAverageClientProjectBudget(projects) {
  if (projects.length === 0) return 0;

  const total = projects.reduce((sum, project) => {
    return sum + ((project.budget_from + project.budget_to) / 2);
  }, 0);

  return Math.round(total / projects.length);
}
function calculateClientProjectTypeDistribution(projects) {
  const typeMap = {};

  projects.forEach(project => {
    const type = project.project_type;
    typeMap[type] = (typeMap[type] || 0) + 1;
  });

  return Object.entries(typeMap)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({ type, count }));
}
function calculateBudgetDistribution(projects) {
  const ranges = [
    { range: '0-500', min: 0, max: 500, count: 0 },
    { range: '501-1000', min: 501, max: 1000, count: 0 },
    { range: '1001-5000', min: 1001, max: 5000, count: 0 },
    { range: '5000+', min: 5001, max: Infinity, count: 0 }
  ];

  projects.forEach(project => {
    const avgBudget = (project.budget_from + project.budget_to) / 2;
    for (const range of ranges) {
      if (avgBudget >= range.min && avgBudget <= range.max) {
        range.count++;
        break;
      }
    }
  });

  return ranges;
}
function calculateFreelancerStats(bids) {
  const freelancerMap = {};

  bids.forEach(bid => {
    if (bid.freelancer) {
      const freelancerId = bid.freelancer._id || bid.freelancer;
      if (!freelancerMap[freelancerId]) {
        freelancerMap[freelancerId] = {
          id: freelancerId,
          name: bid.freelancer.fullName,
          bids: 0,
          accepted: 0,
          totalAmount: 0
        };
      }
      freelancerMap[freelancerId].bids++;
      if (bid.status === 'accepted') {
        freelancerMap[freelancerId].accepted++;
        freelancerMap[freelancerId].totalAmount += bid.amount;
      }
    }
  });

  return Object.values(freelancerMap)
    .sort((a, b) => b.bids - a.bids)
    .slice(0, 10);
}
function getTopFreelancers(bids) {
  const acceptedBids = bids.filter(bid => bid.status === 'accepted');
  const freelancerMap = {};

  acceptedBids.forEach(bid => {
    if (bid.freelancer) {
      const freelancerId = bid.freelancer._id || bid.freelancer;
      if (!freelancerMap[freelancerId]) {
        freelancerMap[freelancerId] = {
          id: freelancerId,
          name: bid.freelancer.fullName,
          projects: 0,
          totalEarned: 0,
          skills: bid.freelancer.skills || [],
          hourlyRate: bid.freelancer.hourlyRate || 0
        };
      }
      freelancerMap[freelancerId].projects++;
      freelancerMap[freelancerId].totalEarned += bid.amount;
    }
  });

  return Object.values(freelancerMap)
    .sort((a, b) => b.totalEarned - a.totalEarned)
    .slice(0, 5);
}
function analyzeHiringPatterns(acceptedBids) {
  if (acceptedBids.length === 0) return {};

  // Calculate average time to accept a bid
  const totalTime = acceptedBids.reduce((sum, bid) => {
    return sum + (bid.updatedAt - bid.createdAt);
  }, 0);
  const averageTimeMs = totalTime / acceptedBids.length;

  // Calculate bid amount vs project budget ratio
  const budgetRatios = acceptedBids.map(bid => {
    if (bid.project && bid.project.budget_from && bid.project.budget_to) {
      const avgBudget = (bid.project.budget_from + bid.project.budget_to) / 2;
      return bid.amount / avgBudget;
    }
    return 1;
  });
  const averageRatio = budgetRatios.reduce((sum, ratio) => sum + ratio, 0) / budgetRatios.length;

  return {
    averageTimeToAccept: formatDuration(averageTimeMs),
    averageBidVsBudgetRatio: averageRatio.toFixed(2),
    mostCommonSkills: calculateSkillsDistribution(acceptedBids).slice(0, 3)
  };
}
async function calculateAverageTimeToHire(projects, bids) {
  if (projects.length === 0) return 'N/A';

  const projectTimes = [];

  for (const project of projects) {
    const projectBids = bids.filter(bid => bid.project.equals(project._id));
    if (projectBids.length > 0) {
      const firstBidTime = projectBids.reduce((min, bid) =>
        bid.createdAt < min ? bid.createdAt : min,
        projectBids[0].createdAt
      );
      const acceptedBid = projectBids.find(bid => bid.status === 'accepted');
      if (acceptedBid) {
        projectTimes.push(acceptedBid.createdAt - firstBidTime);
      }
    }
  }

  if (projectTimes.length === 0) return 'N/A';
  const averageMs = projectTimes.reduce((sum, time) => sum + time, 0) / projectTimes.length;
  return formatDuration(averageMs);
}
function calculateClientProjectCompletionRate(projects, acceptedBids) {
  // This would need a 'completed' status for projects
  // Simplified version - percentage of projects with accepted bids
  if (projects.length === 0) return 0;
  return Math.round((acceptedBids.length / projects.length) * 100);
}
function calculateFreelancerSatisfaction(bids) {
  // This would need feedback from freelancers
  // Simplified version - percentage of bids that were accepted
  if (bids.length === 0) return 0;
  const accepted = bids.filter(bid => bid.status === 'accepted').length;
  return Math.round((accepted / bids.length) * 100);
}
async function calculateAverageClientResponseTime(projects, bids) {
  if (projects.length === 0) return 'N/A';

  const responseTimes = [];

  for (const project of projects) {
    const projectBids = bids.filter(bid => bid.project.equals(project._id));
    if (projectBids.length > 0) {
      const firstBidTime = projectBids.reduce((min, bid) =>
        bid.createdAt < min ? bid.createdAt : min,
        projectBids[0].createdAt
      );
      const acceptedBid = projectBids.find(bid => bid.status === 'accepted');
      if (acceptedBid) {
        responseTimes.push(acceptedBid.createdAt - firstBidTime);
      }
    }
  }

  if (responseTimes.length === 0) return 'N/A';
  const averageMs = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;
  return formatDuration(averageMs);
}
async function getProjectActivity(userEmail, days) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  const projects = await Project.aggregate([
    {
      $match: {
        email: userEmail,
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
        count: { $sum: 1 }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  return projects;
}
async function getSpendingOverTime(userEmail, months) {
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - months);

  const spending = await Bid.aggregate([
    {
      $lookup: {
        from: 'projects',
        localField: 'project',
        foreignField: '_id',
        as: 'project'
      }
    },
    { $unwind: '$project' },
    {
      $match: {
        'project.email': userEmail,
        status: 'accepted',
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
        amount: { $sum: "$amount" }
      }
    },
    { $sort: { _id: 1 } }
  ]);

  return spending;
}
function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds} seconds`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minutes`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hours`;

  const days = Math.floor(hours / 24);
  return `${days} days`;
}
const taskStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = 'uploads/tasks';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});
const taskUpload = multer({
  storage: taskStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB max for task attachments
  },
  fileFilter: (req, file, cb) => {
    const allowedFileTypes = /jpeg|jpg|png|pdf|doc|docx|zip|rar|txt/;
    const extname = allowedFileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedFileTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Only documents, images, and archives are allowed'));
    }
  }
});
app.post('/api/tasks', verifyToken, taskUpload.array('attachments', 5), async (req, res) => {
  try {
    const { projectId, bidId, title, description, priority, dueDate, assignedTo } = req.body;

    // Validate required fields
    if (!projectId || !bidId || !title || !assignedTo) {
      return res.status(400).json({
        success: false,
        message: 'Project ID, Bid ID, Title, and Assigned To are required'
      });
    }

    // Verify the project exists and user has access
    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({
        success: false,
        message: 'Project not found'
      });
    }

    // Verify the bid exists and is accepted
    const bid = await Bid.findById(bidId);
    if (!bid || bid.status !== 'accepted') {
      return res.status(400).json({
        success: false,
        message: 'Bid not found or not accepted'
      });
    }

    // Verify the assigned user exists
    const assignedUser = await User.findById(assignedTo);
    if (!assignedUser) {
      return res.status(404).json({
        success: false,
        message: 'Assigned user not found'
      });
    }

    // Check if the current user is the project owner or has permission
    const currentUser = await User.findById(req.user.id);
    if (project.email !== currentUser.email && currentUser.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to create tasks for this project'
      });
    }

    // Process attachments
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: `/uploads/tasks/${file.filename}`
    })) : [];

    // Create the task
    const task = await Task.create({
      project: projectId,
      bid: bidId,
      title,
      description,
      priority,
      dueDate: dueDate ? new Date(dueDate) : null,
      assignedTo,
      assignedBy: req.user.id,
      attachments
    });

    // Populate the task with user details
    await task.populate([
      { path: 'assignedTo', select: 'fullName email profilePhoto' },
      { path: 'assignedBy', select: 'fullName email profilePhoto' }
    ]);

    // Emit socket event for real-time updates
    io.to(`user_${assignedTo}`).emit('new_task', {
      task,
      message: `New task assigned: ${title}`
    });

    res.status(201).json({
      success: true,
      message: 'Task created successfully',
      data: task
    });

  } catch (error) {
    console.error('Error creating task:', error);

    // Delete uploaded files if there was an error
    if (req.files) {
      req.files.forEach(file => {
        if (fs.existsSync(file.path)) {
          try {
            fs.unlinkSync(file.path);
          } catch (deleteErr) {
            console.error('Error deleting uploaded file:', deleteErr);
          }
        }
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to create task',
      error: error.message
    });
  }
});
app.post('/api/freelancer/projects', async (req, res) => {
  try {
    const { userId } = req.body;

    // Verify user is a freelancer
    const user = await User.findById(userId);
    if (!user || user.role !== 'freelancer') {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Only freelancers can access this endpoint.'
      });
    }

    // Find accepted bids for the freelancer
    const acceptedBids = await Bid.find({
      freelancer: userId,
      status: 'accepted'
    }).populate('project');

    // Extract unique projects from accepted bids
    const projects = acceptedBids.map(bid => bid.project);

    res.status(200).json({
      success: true,
      message: 'Accepted projects fetched successfully',
      data: projects
    });

  } catch (error) {
    console.error('Error fetching accepted projects:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch accepted projects',
      error: error.message
    });
  }
})
app.get('/api/projects/:projectId/tasks', async (req, res) => {
  try {
    const { projectId } = req.params;
    const { status, assignedTo } = req.query;

    const project = await Project.findById(projectId);
    if (!project) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    // ✅ Removed req.user checks
    const filter = { project: projectId };
    if (status) filter.status = status;
    if (assignedTo) filter.assignedTo = assignedTo;

    const tasks = await Task.find(filter)
      .populate('assignedTo', 'fullName email profilePhoto')
      .populate('assignedBy', 'fullName email profilePhoto')
      .populate('bid', 'amount deliveryTime')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      message: 'Tasks fetched successfully',
      data: tasks
    });

  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch tasks', error: error.message });
  }
});
app.get('/api/users/tasks', async (req, res) => {
  try {
    const { type = 'assigned', status, page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Build filter based on task type
    let filter = {};

    if (type === 'assigned') {
      filter.assignedTo = req.user.id;
    } else if (type === 'created') {
      filter.assignedBy = req.user.id;
    } else {
      // Both assigned and created tasks
      filter.$or = [
        { assignedTo: req.user.id },
        { assignedBy: req.user.id }
      ];
    }

    if (status) {
      filter.status = status;
    }

    // Get tasks with pagination
    const tasks = await Task.find(filter)
      .populate('project', 'title project_id')
      .populate('assignedTo', 'fullName email profilePhoto')
      .populate('assignedBy', 'fullName email profilePhoto')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get total count for pagination
    const totalTasks = await Task.countDocuments(filter);

    res.status(200).json({
      success: true,
      message: 'Tasks fetched successfully',
      data: tasks,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalTasks / parseInt(limit)),
        totalTasks,
        tasksPerPage: parseInt(limit)
      }
    });

  } catch (error) {
    console.error('Error fetching user tasks:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tasks',
      error: error.message
    });
  }
});
app.get('/api/tasks/:taskId', async (req, res) => {
  try {
    const { taskId } = req.params;

    const task = await Task.findById(taskId)
      .populate('project', 'title description project_id')
      .populate('bid', 'amount deliveryTime coverLetter')
      .populate('assignedTo', 'fullName email profilePhone title skills')
      .populate('assignedBy', 'fullName email profilePhone title')
      .populate({
        path: 'comments.user',
        select: 'fullName email profilePhoto'
      });

    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // 🚨 Removed access check (req.user), now it just returns the task
    // res.status(200).json({
    //   success: true,
    //   message: 'Task fetched successfully',
    //   data: task
    // });
    res.status(200).json({
      success: true,
      message: 'Task fetched successfully',
      data: {
        ...task.toObject(),
        attachments: task.attachments.map(att => ({
          ...att.toObject(),
          url: `${req.protocol}://${req.get('host')}${att.path}`
        }))
      }
    });

  } catch (error) {
    console.error('Error fetching task:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch task',
      error: error.message
    });
  }
});
app.put('/api/tasks/:taskId/status', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status, rejectedReason } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        message: 'Status is required'
      });
    }

    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // ❌ Skipping permission checks since no req.user
    // Directly allow status update

    // Validate status transitions
    const validTransitions = {
      'pending': ['in_progress', 'rejected'],
      'in_progress': ['completed', 'rejected'],
      'completed': ['pending', 'rejected'],
      'rejected': ['pending', 'in_progress']
    };

    if (!validTransitions[task.status]?.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status transition from ${task.status} to ${status}`
      });
    }

    // Update task
    task.status = status;

    if (status === 'completed') {
      task.completionProof = task.completionProof || {};
      task.completionProof.submittedAt = new Date();
    } else if (status === 'rejected' && rejectedReason) {
      task.rejectedReason = rejectedReason;
    } else if (status === 'approved') {
      task.approvedAt = new Date();
    }

    await task.save();

    // Just emit update without req.user
    io.emit('task_updated', {
      taskId: task._id,
      status,
      updatedBy: "system" // or task.assignedBy / assignedTo if you want
    });

    res.status(200).json({
      success: true,
      message: `Task status updated to ${status}`,
      data: task
    });

  } catch (error) {
    console.error('Error updating task status:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update task status',
      error: error.message
    });
  }
});
app.post('/api/tasks/:taskId/comments', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({
        success: false,
        message: 'Comment content is required'
      });
    }

    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Check if user has access to the task
    const currentUser = await User.findById(req.user.id);
    const hasAccess = (
      task.assignedTo.toString() === req.user.id ||
      task.assignedBy.toString() === req.user.id ||
      currentUser.role === 'admin'
    );

    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to comment on this task'
      });
    }

    // Add comment
    task.comments.push({
      user: req.user.id,
      content
    });

    await task.save();

    // Populate the new comment with user info
    await task.populate({
      path: 'comments.user',
      select: 'fullName email profilePhoto'
    });

    const newComment = task.comments[task.comments.length - 1];

    // Emit socket event for real-time updates
    const otherUserId = task.assignedTo.toString() === req.user.id
      ? task.assignedBy
      : task.assignedTo;

    io.to(`user_${otherUserId}`).emit('new_comment', {
      taskId: task._id,
      comment: newComment
    });

    res.status(201).json({
      success: true,
      message: 'Comment added successfully',
      data: newComment
    });

  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add comment',
      error: error.message
    });
  }
});
app.post('/api/tasks/:taskId/completion-proof', taskUpload.array('attachments', 5), async (req, res) => {
  try {
    const { taskId } = req.params;
    const { description } = req.body;

    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    // Check if user is assigned to the task
    if (task.assignedTo.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Only the assigned user can add completion proof'
      });
    }

    // Process attachments
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      path: `/uploads/tasks/${file.filename}`
    })) : [];

    // Update completion proof
    task.completionProof = {
      description: description || '',
      attachments: [...(task.completionProof?.attachments || []), ...attachments],
      submittedAt: new Date()
    };

    // Change status to completed if not already
    if (task.status !== 'completed') {
      task.status = 'completed';
    }

    await task.save();

    // Emit socket event for real-time updates
    io.to(`user_${task.assignedBy}`).emit('completion_proof_added', {
      taskId: task._id,
      proof: task.completionProof
    });

    res.status(200).json({
      success: true,
      message: 'Completion proof added successfully',
      data: task.completionProof
    });

  } catch (error) {
    console.error('Error adding completion proof:', error);

    // Delete uploaded files if there was an error
    if (req.files) {
      req.files.forEach(file => {
        if (fs.existsSync(file.path)) {
          try {
            fs.unlinkSync(file.path);
          } catch (deleteErr) {
            console.error('Error deleting uploaded file:', deleteErr);
          }
        }
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to add completion proof',
      error: error.message
    });
  }
});
app.get('/api/tasks/statistics', async (req, res) => {
  try {
    const userId = req.user.id;

    const [assignedTasks, createdTasks] = await Promise.all([
      // Tasks assigned to user
      Task.aggregate([
        { $match: { assignedTo: new mongoose.Types.ObjectId(userId) } },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]),

      // Tasks created by user
      Task.aggregate([
        { $match: { assignedBy: new mongoose.Types.ObjectId(userId) } },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ])
    ]);

    // Format the results
    const formatStats = (stats) => {
      const statuses = ['pending', 'in_progress', 'completed', 'rejected'];
      const result = {};

      statuses.forEach(status => {
        const stat = stats.find(s => s._id === status);
        result[status] = stat ? stat.count : 0;
      });

      result.total = Object.values(result).reduce((sum, count) => sum + count, 0);

      return result;
    };

    res.status(200).json({
      success: true,
      data: {
        assigned: formatStats(assignedTasks),
        created: formatStats(createdTasks)
      }
    });

  } catch (error) {
    console.error('Error fetching task statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch task statistics',
      error: error.message
    });
  }
});
app.get('/user/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const { status, priority, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Find the user by email → fetch id, name, email
    const user = await User.findOne({ email }).select('_id name email avatar');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Build the query filter (tasks created/assigned by this user)
    const filter = { assignedBy: user._id };

    if (status) filter.status = status;
    if (priority) filter.priority = priority;

    // Build sort options
    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;

    // Fetch tasks with populated fields
    const tasks = await Task.find(filter)
      .populate({
        path: 'project',
        select: 'title description budget deadline client'
      })
      .populate({
        path: 'bid',
        select: 'amount proposedTimeline status'
      })
      .populate({
        path: 'assignedBy',
        select: 'name email avatar' // includes name
      })
      .populate({
        path: 'assignedTo',
        select: 'fullName email avatar' // ✅ includes name
      })
      .populate({
        path: 'comments.user',
        select: 'name avatar'
      })
      .sort(sortOptions)
      .lean();

    // Aggregate statistics → tasks assigned *to* this user
    const stats = await Task.aggregate([
      { $match: { assignedTo: user._id } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          completed: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
          inProgress: { $sum: { $cond: [{ $eq: ['$status', 'in_progress'] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
          rejected: { $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] } },
          highPriority: { $sum: { $cond: [{ $eq: ['$priority', 'high'] }, 1, 0] } },
          mediumPriority: { $sum: { $cond: [{ $eq: ['$priority', 'medium'] }, 1, 0] } },
          lowPriority: { $sum: { $cond: [{ $eq: ['$priority', 'low'] }, 1, 0] } },
          overdue: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $lt: ['$dueDate', new Date()] },
                    { $ne: ['$status', 'completed'] }
                  ]
                },
                1,
                0
              ]
            }
          }
        }
      }
    ]);

    const taskStats = stats.length > 0 ? stats[0] : {
      total: 0,
      completed: 0,
      inProgress: 0,
      pending: 0,
      rejected: 0,
      highPriority: 0,
      mediumPriority: 0,
      lowPriority: 0,
      overdue: 0
    };

    // Response → includes name, email, avatar
    res.status(200).json({
      success: true,
      message: 'Tasks retrieved successfully',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          avatar: user.avatar
        },
        tasks,
        stats: taskStats
      }
    });

  } catch (error) {
    console.error('Error fetching user tasks:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Update project status API
app.put('/api/complete_project/:id', async (req, res) => {
  try {
    const { id } = req.params; // Use params, not query

    // Find project by project_id
    const project = await Project.findOne({ project_id: id });

    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }

    // Fetch all tasks associated with the project
    const tasks = await Task.find({ project: project._id });

    // Condition 1: Project must have at least one task
    if (tasks.length === 0) {
      return res.status(400).json({ message: 'Cannot complete project: No tasks found for this project.' });
    }

    // Condition 2: All tasks must be completed
    const allCompleted = tasks.every(task => task.status === 'completed');
    if (!allCompleted) {
      return res.status(400).json({ message: 'Cannot complete project: All tasks must have status "completed".' });
    }

    // Update project status to completed
    const updatedProject = await Project.findOneAndUpdate(
      { project_id: id }, // filter
      { $set: { status: 'completed' } }, // update
      { new: true } // return updated doc
    );

    if (!updatedProject) {
      return res.status(404).json({ message: 'Project not found after update.' });
    }

    res.status(200).json({
      message: 'Project marked as completed',
      project: updatedProject
    });
  } catch (error) {
    console.error('Error updating project status:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});