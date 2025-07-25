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
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
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
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173','*'], // Add your frontend URL
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
  destination: function(req, file, cb) {
    // Create specific folder for profile photos
    const uploadPath = file.fieldname === 'profilePhoto' ? 'uploads/profiles' : 'uploads';
    
    // Ensure directory exists
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    cb(null, uploadPath);
  },
  filename: function(req, file, cb) {
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
mongoose.connect('mongodb://localhost:27017/freelance-platform', {
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
    enum: ['user', 'admin'],
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
userSchema.virtual('profileCompleteness').get(function() {
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
userSchema.pre('save', async function(next) {
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
userSchema.methods.comparePassword = async function(candidatePassword) {
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
  project_id: {
  type: String,
  required: true,
  unique: true
}

}, { timestamps: true });

const Project = mongoose.model('Project', projectSchema);

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
// Role-based authorization middleware
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
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
app.get('/api/projects/with-profiles', async (req, res) => {
  try {
    // Fetch all projects sorted by creation date (latest first)
    const projects = await Project.find().sort({ createdAt: -1 });
    
    // If no projects found
    if (!projects || projects.length === 0) {
      return res.status(200).json({
        success: true,
        message: 'No projects found',
        data: []
      });
    }

    // Enhance each project with user profile data
    const enhancedProjects = await Promise.all(
      projects.map(async (project) => {
        try {
          // Find user by email from the project
          const user = await User.findOne({ email: project.email })
            .select('fullName profilePhoto reviews email title location skills');
          
          // Calculate average rating from reviews
          let averageRating = 0;
          let totalReviews = 0;
          
          if (user && user.reviews && user.reviews.length > 0) {
            const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
            totalReviews = user.reviews.length;
            averageRating = (totalRating / totalReviews).toFixed(1);
          }

          // Convert project to object and add user data
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
            }
          };
        } catch (userError) {
          console.error(`Error fetching user data for project ${project._id}:`, userError);
          
          // Return project with default user data if user fetch fails
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
            }
          };
        }
      })
    );

    res.status(200).json({
      success: true,
      message: 'Projects fetched successfully',
      data: enhancedProjects,
      count: enhancedProjects.length
    });

  } catch (error) {
    console.error('Error fetching projects with profiles:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch projects',
      error: error.message
    });
  }
});
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
app.get('/api/projects/:id/with-profile', async (req, res) => {
  try {
    const { id } = req.params;

    // Validate project ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid project ID'
      });
    }

    // Find the project
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({
        success: false,
        message: 'Project not found'
      });
    }

    // Find user by email from the project
    const user = await User.findOne({ email: project.email })
      .select('fullName profilePhoto reviews email title location skills hourlyRate bio availabilityPerWeek');
    
    // Calculate average rating from reviews
    let averageRating = 0;
    let totalReviews = 0;
    
    if (user && user.reviews && user.reviews.length > 0) {
      const totalRating = user.reviews.reduce((sum, review) => sum + review.rating, 0);
      totalReviews = user.reviews.length;
      averageRating = (totalRating / totalReviews).toFixed(1);
    }

    // Convert project to object and add user data
    const projectObj = project.toObject();
    
    const enhancedProject = {
      ...projectObj,
      userProfile: user ? {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        title: user.title,
        bio: user.bio,
        location: user.location,
        skills: user.skills,
        hourlyRate: user.hourlyRate,
        availabilityPerWeek: user.availabilityPerWeek,
        profilePhoto: user.profilePhoto,
        rating: {
          average: parseFloat(averageRating),
          totalReviews: totalReviews,
          reviews: user.reviews.map(review => ({
            clientName: review.clientName,
            clientAvatar: review.clientAvatar,
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
        bio: null,
        location: null,
        skills: [],
        hourlyRate: null,
        availabilityPerWeek: null,
        profilePhoto: null,
        rating: {
          average: 0,
          totalReviews: 0,
          reviews: []
        }
      }
    };

    res.status(200).json({
      success: true,
      message: 'Project fetched successfully',
      data: enhancedProject
    });

  } catch (error) {
    console.error('Error fetching project with profile:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch project',
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
});
app.get('/api/chat/stats', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const [totalConversations, unreadMessages, activeChats] = await Promise.all([
      Conversation.countDocuments({ participants: userId }),
      Message.countDocuments({
        conversation: { $in: await Conversation.find({ participants: userId }).select('_id') },
        sender: { $ne: userId },
        read: false
      }),
      Conversation.countDocuments({
        participants: userId,
        updatedAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Last 7 days
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

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});