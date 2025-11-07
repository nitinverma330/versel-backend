const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// ✅ Enhanced CORS configuration for production
const allowedOrigins = [
  'http://localhost:3000',
  'https://versel-frontend-tau.vercel.app',
  'https://versel-frontend.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = `The CORS policy for this site does not allow access from ${origin}`;
      console.log('❌ CORS Blocked:', origin);
      return callback(new Error(msg), false);
    }
    console.log('✅ CORS Allowed:', origin);
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());

// ✅ Root route to fix "Cannot GET /"
app.get('/', (req, res) => {
  res.json({ 
    message: '✅ QR Attendance Backend is running!',
    status: 'active',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/login, /api/register, /api/temp-login',
      attendance: '/api/attendance, /api/sessions',
      students: '/api/students, /api/profile',
      export: '/api/export/:session'
    }
  });
});

// ✅ IMPROVED MongoDB Connection with timeout handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://nv1189766_db_user:UPlUuYeGrJREQDn9@cluster0.rjbh1pj.mongodb.net/AT_Project?retryWrites=true&w=majority&appName=Cluster0';

console.log('🔧 Attempting MongoDB connection...');
console.log('📊 MongoDB URI:', MONGODB_URI ? 'Provided' : 'Using default');

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000, // 30 seconds
  socketTimeoutMS: 45000, // 45 seconds
  bufferCommands: false,
  bufferMaxEntries: 0
})
.then(() => {
  console.log('✅ MongoDB Connected Successfully');
  console.log('📊 Database Name:', mongoose.connection.name);
  console.log('🔌 MongoDB Host:', mongoose.connection.host);
})
.catch(err => {
  console.error('❌ MongoDB Connection Error:', err.message);
  console.log('💡 Tip: Set MONGODB_URI environment variable for production');
});

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Database Schemas

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['teacher', 'student'], required: true },
  name: { type: String, required: true },
  email: { type: String },
  rollNumber: { type: String },
  course: { type: String },
  section: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  roll: { type: String, required: true },
  session: { type: String, required: true },
  course: { type: String, required: true },
  section: { type: String, required: true },
  subject: { type: String, required: true },
  faculty: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  scanTime: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const Attendance = mongoose.model('Attendance', attendanceSchema);

// Session Schema
const sessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  course: { type: String, required: true },
  section: { type: String, required: true },
  subject: { type: String, required: true },
  faculty: { type: String, required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  note: { type: String },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Session = mongoose.model('Session', sessionSchema);

// Complete student list
const allStudents = [
  { "student_id": "BC2023003", "name": "AYUSH AGARWAL" },
  { "student_id": "BC2023022", "name": "ANKIT KUMAR MAURYA" },
  { "student_id": "BC2023034", "name": "NISHTHA AGARWAL" },
  { "student_id": "BC2023037", "name": "ABHAY MISHRA" },
  { "student_id": "BC2023038", "name": "RONIT MAURYA" },
  { "student_id": "BC2023051", "name": "DHARMESH KUSHWAHA" },
  { "student_id": "BC2023060", "name": "PAVAS SHARMA" },
  { "student_id": "BC2023064", "name": "KABIR MOHSIN" },
  { "student_id": "BC2023071", "name": "DIVYANSH PANDEY" },
  { "student_id": "BC2023072", "name": "AKSHAT CHANDAK" },
  { "student_id": "BC2023116", "name": "PANKAJ RATHOUR" },
  { "student_id": "BC2023129", "name": "PRAKASH MISHRA" },
  { "student_id": "BC2023177", "name": "ANUSHKA TANDON" },
  { "student_id": "BC2023189", "name": "ANUJ KUSHWAHA" },
  { "student_id": "BC2023204", "name": "HARSHITA CHAND" },
  { "student_id": "BC2023205", "name": "AMISHA CHAND" },
  { "student_id": "BC2023210", "name": "CHAHNA CHAND" },
  { "student_id": "BC2023215", "name": "MRADUL SHARMA" },
  { "student_id": "BC2023219", "name": "PALAK KUMARI" },
  { "student_id": "BC2023223", "name": "AMAN VERMA" },
  { "student_id": "BC2023233", "name": "KUMARI SONI" },
  { "student_id": "BC2023238", "name": "AYAN KHAN" },
  { "student_id": "BC2023251", "name": "SHAZEEM KHAN" },
  { "student_id": "BC2023254", "name": "SAKSHAM SHARMA" },
  { "student_id": "BC2023255", "name": "SHIVAM PRAJAPATI" },
  { "student_id": "BC2023257", "name": "HARSHIT MISHRA" },
  { "student_id": "BC2023262", "name": "AASTIK MISHRA" },
  { "student_id": "BC2023265", "name": "KUSHAGRA GANGWAR" },
  { "student_id": "BC2023270", "name": "MOHD YASIR" },
  { "student_id": "BC2023284", "name": "MOHD ADNAN ASHRAF" },
  { "student_id": "BC2023285", "name": "MOHSIN" },
  { "student_id": "BC2023290", "name": "MADHU KUMARI" },
  { "student_id": "BC2023326", "name": "ARYAN GANGWAR" },
  { "student_id": "BC2023327", "name": "KAUSHAL KUMAR" },
  { "student_id": "BC2023329", "name": "AMAN KUMAR" },
  { "student_id": "BC2023330", "name": "VINEET PUNDHIR" },
  { "student_id": "BC2023333", "name": "MANDEEP KUMAR" },
  { "student_id": "BC2023335", "name": "AYUSH SHARMA" },
  { "student_id": "BC2023338", "name": "SAMI KHAN" },
  { "student_id": "BC2023339", "name": "NITIN VERMA" },
  { "student_id": "BC2023342", "name": "MANAS GANGWAR" },
  { "student_id": "BC2023348", "name": "NIRANJAN SINGH RAWAT" },
  { "student_id": "BC2023351", "name": "RYYAN KHAN" },
  { "student_id": "BC2023355", "name": "MUSKAN VERMA" },
  { "student_id": "BC2023358", "name": "VIKAS SHARMA" },
  { "student_id": "BC2023364", "name": "VIKAS VERMA" },
  { "student_id": "BC2023375", "name": "SHIVANI VERMA" },
  { "student_id": "BC2023380", "name": "SONU RAJPOOT" },
  { "student_id": "BC2023396", "name": "ALOK YADAV" },
  { "student_id": "BC2023397", "name": "LALIT SHARMA" },
  { "student_id": "BC2023406", "name": "RITIK SHUKLA" },
  { "student_id": "BC2023414", "name": "SHRUTYANSH MOHAN PATHAK" },
  { "student_id": "BC2023425", "name": "RUDRANSH DWIVEDI" },
  { "student_id": "BC2023427", "name": "ANSHI SINGH" },
  { "student_id": "BC2023428", "name": "LAVI SINGH" },
  { "student_id": "BC2023429", "name": "ABHISHEK SINGH" },
  { "student_id": "BC2023434", "name": "SIMRAN VERMA" },
  { "student_id": "BC2023436", "name": "PRANJAL VERMA" },
  { "student_id": "BC2023441", "name": "AJAY DEV" },
  { "student_id": "BC2023453", "name": "KAMAL KANT" },
  { "student_id": "BC2023456", "name": "VIDHI GUPTA" },
  { "student_id": "BC2023460", "name": "UNNATI SAXENA" },
  { "student_id": "BC2023461", "name": "ABHISHEK SHARMA" },
  { "student_id": "BC2023465", "name": "PIYUSH JAISWAL" },
  { "student_id": "BC2023468", "name": "SYED SAIM HUSSAIN" },
  { "student_id": "BC2023474", "name": "NITIN SAGAR" },
  { "student_id": "BC2023479", "name": "SAUMYA SINGH" },
  { "student_id": "BC2023485", "name": "VISHESH PANT" },
  { "student_id": "BC2023493", "name": "NISHANT GANGWAR" },
  { "student_id": "BC2023498", "name": "ANAMTA YUSUF" },
  { "student_id": "BC2023502", "name": "SHOURYA PATHAK" },
  { "student_id": "BC2023509", "name": "SHAGUN GANGWAR" },
  { "student_id": "BC2023512", "name": "NIMRA HIFZAN" },
  { "student_id": "BC2023517", "name": "ARYAN TIWARI" },
  { "student_id": "BC2023520", "name": "ROUNAK" },
  { "student_id": "BC2023528", "name": "BHUWANESHWARI KASHYAP" },
  { "student_id": "BC2023529", "name": "SIMRAN ARORA" },
  { "student_id": "BC2023537", "name": "AAKANKSHA" },
  { "student_id": "BC2023550", "name": "VANSH SAXENA" },
  { "student_id": "BC2023555", "name": "SHALIV ALI" },
  { "student_id": "BC2023565", "name": "VANSH AGARWAL" },
  { "student_id": "BC2023566", "name": "TAYYABA FATIMA" },
  { "student_id": "BC2023574", "name": "ADITYA PRAJAPATI" },
  { "student_id": "BC2023577", "name": "AKSHARA GUPTA" },
  { "student_id": "BC2023589", "name": "AINA GUPTA" },
  { "student_id": "BC2023591", "name": "MOHD KAIF" },
  { "student_id": "BC2023596", "name": "SHIVAM MAURYA" },
  { "student_id": "BC2023609", "name": "ARUN GANGWAR" },
  { "student_id": "BC2023618", "name": "SUMIT SAXENA" },
  { "student_id": "BC2023627", "name": "KHYATI SINGH" },
  { "student_id": "BC2023629", "name": "DHEERAJ YADAV" },
  { "student_id": "BC2023635", "name": "SHIVA MADDHESHIYA" },
  { "student_id": "BC2023642", "name": "GOVIND GUPTA" },
  { "student_id": "BC2023654", "name": "AYUSHI KOHARWAL" },
  { "student_id": "BC2023656", "name": "SACHIN KHARWAR" },
  { "student_id": "BC2023657", "name": "SHASHANK RAJPUT" },
  { "student_id": "BC2023666", "name": "SYED TANZIM WAJIH" },
  { "student_id": "BC2023684", "name": "HEMANT KUMAR BHARTI" },
  { "student_id": "BC2023685", "name": "NISHA KASHYAP" },
  { "student_id": "BC2023701", "name": "VISHAL BHOJWANI" },
  { "student_id": "BC2023075", "name": "SHIVA YADAV" },
  { "student_id": "BC2023250", "name": "RAJAN SINGH" }
];

// ✅ TEMPORARY IN-MEMORY STORAGE (Works without MongoDB)
let temporaryUsers = [];
let temporarySessions = [];
let temporaryAttendance = [];

// Initialize temporary storage with demo data
const initializeTemporaryStorage = () => {
  console.log('💾 Initializing temporary in-memory storage...');
  
  // Add admin user
  temporaryUsers.push({
    username: 'admin',
    password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lewd.fvWrIVyKTqOS', // admin123
    role: 'teacher',
    name: 'Administrator',
    email: 'admin@school.edu',
    rollNumber: 'ADMIN001',
    course: 'ALL',
    section: 'A'
  });

  // Add all students to temporary storage
  allStudents.forEach(student => {
    temporaryUsers.push({
      username: student.student_id,
      password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/Lewd.fvWrIVyKTqOS', // student123
      role: 'student',
      name: student.name,
      email: `${student.student_id.toLowerCase()}@school.edu`,
      rollNumber: student.student_id,
      course: 'BCA',
      section: 'A'
    });
  });

  // Add some demo sessions
  const demoSession = {
    sessionId: 'DEMO-SESSION-001',
    course: 'BCA',
    section: 'A',
    subject: 'MERN-Fullstack',
    faculty: 'Dr. Smith',
    date: new Date().toISOString().split('T')[0],
    time: '10:00 AM - 11:00 AM',
    note: 'Demo session for testing',
    createdBy: 'admin',
    createdAt: new Date()
  };
  temporarySessions.push(demoSession);

  console.log(`✅ Temporary storage initialized with:
    - ${temporaryUsers.length} users (1 teacher, ${temporaryUsers.length - 1} students)
    - ${temporarySessions.length} demo sessions
    - ${temporaryAttendance.length} attendance records`);
};

// Initialize temporary storage on server start
initializeTemporaryStorage();

// Check if MongoDB is connected
const isMongoConnected = () => {
  return mongoose.connection.readyState === 1;
};

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ status: 'error', message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ status: 'error', message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check if user is teacher
const requireTeacher = (req, res, next) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ status: 'error', message: 'Teacher access required' });
  }
  next();
};

// API Routes

// Test API
app.get('/api/test', (req, res) => {
  res.json({ 
    message: '✅ Backend is working!',
    database: isMongoConnected() ? 'connected' : 'disconnected (using temp storage)',
    storage: isMongoConnected() ? 'MongoDB' : 'In-Memory'
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    database: isMongoConnected() ? 'connected' : 'disconnected',
    storage: isMongoConnected() ? 'MongoDB' : 'In-Memory',
    timestamp: new Date().toISOString(),
    users: isMongoConnected() ? 'From MongoDB' : `From Memory (${temporaryUsers.length})`,
    sessions: isMongoConnected() ? 'From MongoDB' : `From Memory (${temporarySessions.length})`
  });
});

// ✅ Connection test endpoint
app.get('/api/connection-test', (req, res) => {
  res.json({
    status: 'success',
    message: '✅ Backend is connected and responding!',
    backend: 'https://versel-backend-henna.vercel.app',
    frontend: 'https://versel-frontend-tau.vercel.app',
    database: isMongoConnected() ? 'connected' : 'disconnected (using temp storage)',
    storage: isMongoConnected() ? 'MongoDB' : 'In-Memory',
    timestamp: new Date().toISOString()
  });
});

// ✅ TEMPORARY LOGIN (Works without MongoDB)
app.post('/api/temp-login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('🔐 Temp login attempt for:', username);

    // Find user in temporary storage
    const user = temporaryUsers.find(u => u.username === username);
    
    if (!user) {
      console.log('❌ User not found:', username);
      return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
    }

    // Simple password check (in real app, use bcrypt)
    const isPasswordValid = password === 'student123' || password === 'admin123';
    
    if (!isPasswordValid) {
      console.log('❌ Invalid password for:', username);
      return res.status(400).json({ status: 'error', message: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.username, 
        username: user.username, 
        role: user.role,
        name: user.name 
      }, 
      JWT_SECRET, 
      { expiresIn: '24h' }
    );

    console.log('✅ Login successful for:', user.name);

    res.json({
      status: 'success',
      message: 'Login successful',
      data: {
        token,
        user: {
          id: user.username,
          username: user.username,
          role: user.role,
          name: user.name,
          email: user.email,
          rollNumber: user.rollNumber,
          course: user.course,
          section: user.section
        }
      }
    });
  } catch (error) {
    console.error('❌ Temp login error:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Get all sessions
app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    console.log('📚 Fetching sessions...');
    
    if (isMongoConnected()) {
      // Use MongoDB
      let sessions;
      if (req.user.role === 'teacher') {
        sessions = await Session.find({ createdBy: req.user.username }).sort({ createdAt: -1 });
      } else {
        sessions = await Session.find().sort({ createdAt: -1 });
      }
      
      console.log(`✅ Found ${sessions.length} sessions in MongoDB`);
      return res.json({ status: 'success', data: sessions });
    } else {
      // Use temporary storage
      let sessions = [...temporarySessions];
      if (req.user.role === 'teacher') {
        sessions = sessions.filter(session => session.createdBy === req.user.username);
      }
      sessions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
      console.log(`✅ Found ${sessions.length} sessions in temporary storage`);
      return res.json({ status: 'success', data: sessions });
    }
  } catch (error) {
    console.error('❌ Error fetching sessions:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Create new session
app.post('/api/sessions', authenticateToken, requireTeacher, async (req, res) => {
  try {
    console.log('🆕 Creating new session:', req.body);
    
    const sessionData = {
      ...req.body,
      createdBy: req.user.username,
      createdAt: new Date()
    };

    if (isMongoConnected()) {
      // Save to MongoDB
      const session = new Session(sessionData);
      await session.save();
      console.log('✅ Session saved to MongoDB');
      return res.status(201).json({ 
        status: 'success', 
        message: 'Session created successfully',
        data: session 
      });
    } else {
      // Save to temporary storage
      sessionData._id = `temp_${Date.now()}`;
      temporarySessions.push(sessionData);
      console.log('✅ Session saved to temporary storage');
      return res.status(201).json({ 
        status: 'success', 
        message: 'Session created successfully (temporary storage)',
        data: sessionData 
      });
    }
  } catch (error) {
    console.error('❌ Error creating session:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Save attendance
app.post('/api/attendance', authenticateToken, async (req, res) => {
  try {
    console.log('📥 Received attendance data:', req.body);
    
    const attendanceData = {
      ...req.body,
      timestamp: new Date()
    };

    if (isMongoConnected()) {
      // Save to MongoDB
      const attendance = new Attendance(attendanceData);
      await attendance.save();
      console.log('✅ Attendance saved to MongoDB');
      return res.status(201).json({ 
        status: 'success', 
        message: 'Attendance marked successfully',
        data: attendance 
      });
    } else {
      // Save to temporary storage
      attendanceData._id = `temp_att_${Date.now()}`;
      temporaryAttendance.push(attendanceData);
      console.log('✅ Attendance saved to temporary storage');
      return res.status(201).json({ 
        status: 'success', 
        message: 'Attendance marked successfully (temporary storage)',
        data: attendanceData 
      });
    }
  } catch (error) {
    console.error('❌ Error saving attendance:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Get attendance by session
app.get('/api/attendance/:session', authenticateToken, async (req, res) => {
  try {
    const sessionId = req.params.session;
    console.log('📋 Fetching attendance for session:', sessionId);
    
    if (isMongoConnected()) {
      // Get from MongoDB
      let query = { session: sessionId };
      if (req.user.role === 'student') {
        query.roll = req.user.username;
      }
      
      const attendance = await Attendance.find(query).sort({ timestamp: -1 });
      console.log(`✅ Found ${attendance.length} records in MongoDB for session ${sessionId}`);
      return res.json({ status: 'success', data: attendance });
    } else {
      // Get from temporary storage
      let attendance = temporaryAttendance.filter(record => record.session === sessionId);
      if (req.user.role === 'student') {
        attendance = attendance.filter(record => record.roll === req.user.username);
      }
      attendance.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      console.log(`✅ Found ${attendance.length} records in temporary storage for session ${sessionId}`);
      return res.json({ status: 'success', data: attendance });
    }
  } catch (error) {
    console.error('❌ Error fetching attendance:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Get all students (teacher only)
app.get('/api/students', authenticateToken, requireTeacher, async (req, res) => {
  try {
    console.log('👨‍🎓 Fetching students list...');
    
    if (isMongoConnected()) {
      // Get from MongoDB
      const students = await User.find({ role: 'student' }).select('-password').sort({ name: 1 });
      console.log(`✅ Found ${students.length} students in MongoDB`);
      return res.json({ status: 'success', data: students });
    } else {
      // Get from temporary storage
      const students = temporaryUsers
        .filter(user => user.role === 'student')
        .map(({ password, ...user }) => user) // Remove password
        .sort((a, b) => a.name.localeCompare(b.name));
      
      console.log(`✅ Found ${students.length} students in temporary storage`);
      return res.json({ status: 'success', data: students });
    }
  } catch (error) {
    console.error('❌ Error fetching students:', error);
    res.status(400).json({ status: 'error', message: error.message });
  }
});

// Get student statistics
app.get('/api/student-stats/:rollNumber', authenticateToken, async (req, res) => {
  try {
    const { rollNumber } = req.params;
    
    // Verify access - students can only see their own stats
    if (req.user.role === 'student' && req.user.username !== rollNumber) {
      return res.status(403).json({ status: 'error', message: 'Access denied' });
    }
    
    console.log(`📊 Fetching stats for student: ${rollNumber}`);
    
    let studentRecords = [];
    let totalSessions = 0;

    if (isMongoConnected()) {
      // Get from MongoDB
      studentRecords = await Attendance.find({ roll: rollNumber }).sort({ timestamp: -1 });
      totalSessions = await Session.countDocuments();
    } else {
      // Get from temporary storage
      studentRecords = temporaryAttendance.filter(record => record.roll === rollNumber);
      studentRecords.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      totalSessions = temporarySessions.length;
    }

    const stats = {
      totalLectures: totalSessions,
      attendedLectures: studentRecords.length,
      attendancePercentage: totalSessions > 0 ? ((studentRecords.length / totalSessions) * 100).toFixed(1) : 0,
      recentAttendance: studentRecords.slice(0, 10),
      allRecords: studentRecords
    };
    
    console.log('📈 Student stats:', stats);
    res.json({ status: 'success', data: stats });
  } catch (error) {
    console.error('❌ Error fetching student stats:', error);
    res.status(400).json({ status: 'error', message: error.message });
  }
});

// Delete session and its attendance
app.delete('/api/sessions/:sessionId', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const sessionId = req.params.sessionId;
    console.log('🗑️ Deleting session:', sessionId);
    
    if (isMongoConnected()) {
      // Delete from MongoDB
      const session = await Session.findOne({ sessionId: sessionId, createdBy: req.user.username });
      if (!session) {
        return res.status(404).json({ 
          status: 'error', 
          message: 'Session not found or access denied' 
        });
      }
      
      await Session.deleteOne({ sessionId: sessionId });
      await Attendance.deleteMany({ session: sessionId });
    } else {
      // Delete from temporary storage
      const sessionIndex = temporarySessions.findIndex(s => s.sessionId === sessionId && s.createdBy === req.user.username);
      if (sessionIndex === -1) {
        return res.status(404).json({ 
          status: 'error', 
          message: 'Session not found or access denied' 
        });
      }
      
      temporarySessions.splice(sessionIndex, 1);
      temporaryAttendance = temporaryAttendance.filter(record => record.session !== sessionId);
    }
    
    console.log('✅ Session deleted successfully');
    res.json({ 
      status: 'success', 
      message: 'Session and all attendance records deleted successfully' 
    });
  } catch (error) {
    console.error('❌ Error deleting session:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Export attendance as CSV
app.get('/api/export/:session', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const sessionId = req.params.session;
    console.log('📊 Exporting attendance for session:', sessionId);
    
    let attendance = [];
    
    if (isMongoConnected()) {
      attendance = await Attendance.find({ session: sessionId });
    } else {
      attendance = temporaryAttendance.filter(record => record.session === sessionId);
    }
    
    let csv = 'Name,Roll Number,Session,Course,Section,Subject,Faculty,Date,Time,Scan Time\n';
    attendance.forEach(record => {
      csv += `"${record.name}","${record.roll}","${record.session}","${record.course}","${record.section}","${record.subject}","${record.faculty}","${record.date}","${record.time}","${record.scanTime}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=attendance_${sessionId}.csv`);
    res.send(csv);
    
    console.log(`✅ Exported ${attendance.length} records as CSV`);
  } catch (error) {
    console.error('❌ Error exporting attendance:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// Get all attendance records
app.get('/api/attendance', authenticateToken, async (req, res) => {
  try {
    console.log('📋 Fetching all attendance records...');
    
    if (isMongoConnected()) {
      let query = {};
      if (req.user.role === 'student') {
        query.roll = req.user.username;
      }
      
      const allAttendance = await Attendance.find(query).sort({ timestamp: -1 });
      console.log(`✅ Found ${allAttendance.length} total records in MongoDB`);
      return res.json({ status: 'success', data: allAttendance });
    } else {
      let allAttendance = [...temporaryAttendance];
      if (req.user.role === 'student') {
        allAttendance = allAttendance.filter(record => record.roll === req.user.username);
      }
      allAttendance.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      console.log(`✅ Found ${allAttendance.length} total records in temporary storage`);
      return res.json({ status: 'success', data: allAttendance });
    }
  } catch (error) {
    console.error('❌ Error fetching all attendance:', error);
    res.status(400).json({ 
      status: 'error', 
      message: error.message 
    });
  }
});

// 404 handler for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl 
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// ✅ Export the app for Vercel
module.exports = app;

// ✅ Start server only in local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📊 MongoDB Status: ${isMongoConnected() ? 'Connected' : 'Disconnected'}`);
    console.log(`💾 Storage: ${isMongoConnected() ? 'MongoDB' : 'In-Memory (Temporary)'}`);
    console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default'}`);
    console.log(`🌐 CORS Enabled for: ${allowedOrigins.join(', ')}`);
    
    if (!isMongoConnected()) {
      console.log('📝 Demo Credentials:');
      console.log('   👨‍🏫 Teacher: admin / admin123');
      console.log('   👨‍🎓 Student: BC2023003 / student123');
      console.log('   👨‍🎓 Student: BC2023339 / student123');
    }
  });
}
