// server.js - Complete Car Wash Management Backend with Authentication
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
// IMPORTANT: Load environment variables FIRST
require('dotenv').config();

// IMPORTANT: Import logger AFTER dotenv
const morgan = require('morgan');
const { logger, logSecurity, logSlow } = require('./simple-logger');

// ✅ NEW - Authentication dependencies
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const helmet = require('helmet');  // ← ADD THIS LINE

// NOW you can use logger (AFTER importing it)
logger.info('🚀 Car Wash Server Starting', {
  env: process.env.NODE_ENV,
  port: process.env.PORT || 3001
});

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// ✅ ENABLED - Rate limiting for API routes
app.use('/api/', limiter);

// Enhanced rate limiting for authentication
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many login attempts, please try again later.'
});

// CORS configuration
// Dynamic CORS configuration from environment variables
const getCorsOrigins = () => {
  // Read origins from environment variable (comma-separated)
  const envOrigins = process.env.CORS_ORIGINS ? 
    process.env.CORS_ORIGINS.split(',').map(origin => origin.trim()) : [];
  
  // Always include these development origins for local testing
  const defaultOrigins = [
    'http://localhost:3000',
    'http://localhost:3001', 
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3001'
  ];
  
  // Combine and remove duplicates
  return [...new Set([...defaultOrigins, ...envOrigins])];
};

// Call the function to get the origins array
const allowedOrigins = getCorsOrigins();

// Log what origins are allowed (for debugging)
console.log('🔐 CORS allowed origins:', allowedOrigins);
const vercelPattern = /^https:\/\/[a-zA-Z0-9-]+-[a-zA-Z0-9-]+-[a-zA-Z0-9]+\.vercel\.app$/;

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman, etc.)
    if (!origin) return callback(null, true);

    // Normalize origin (remove trailing slash)
    const normalizedOrigin = origin.replace(/\/$/, '');

    // Check if origin is in allowed list
    const isExplicitlyAllowed = allowedOrigins.includes(normalizedOrigin);
    
    // Check if origin matches Vercel pattern (for preview deployments)
    const isVercelPreview = vercelPattern.test(normalizedOrigin);
    
    if (isExplicitlyAllowed || isVercelPreview) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS blocked request from: ${normalizedOrigin}`);
      callback(new Error(`CORS policy violation: Origin ${normalizedOrigin} not allowed`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400 // 24 hours preflight cache
}));

app.use(morgan('combined', { 
  stream: { write: (message) => logger.info(message.trim()) }
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('📁 Created uploads directory');
}

// Multer configuration for photo uploads
// ✅ NEW - Cloudinary configuration

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ✅ NEW - Cloudinary storage for multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'jouini-carwash', // Organize uploads in folders
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [
      {
        width: 1200,
        height: 1200,
        crop: 'limit',
        quality: 'auto:good'
      }
    ]
  }
});

const upload = multer({ 
  storage,
  limits: { 
    fileSize: 10 * 1024 * 1024, // 10MB max (Cloudinary optimizes)
    files: 5 // Max 5 files
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files (JPEG, JPG, PNG, WebP) are allowed'));
    }
  }
});
// Database configuration
const isProduction = process.env.NODE_ENV === 'production';
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});


// ✅ NEW - JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ✅ NEW - Input validation schemas
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(3).max(100).required()
});

const washSchema = Joi.object({
  immatriculation: Joi.string().pattern(/^[A-Z0-9\-\s]{3,15}$/i).required(),
  serviceType: Joi.string().valid('interieur', 'exterieur', 'complet', 'lavage-ville', 'complet-premium').required(),
  vehicleType: Joi.string().valid('voiture', 'camion', 'moto', 'taxi').required(),
  price: Joi.number().positive().optional(),
  photos: Joi.array().items(Joi.string()).optional(),
  motoDetails: Joi.object().optional()
});

// ✅ NEW - Protect API routes with authentication
app.use('/api', (req, res, next) => {
  // Skip authentication for these paths
  const publicPaths = ['/auth/login', '/auth/verify', '/health'];
  const isPublicPath = publicPaths.some(path => req.path.startsWith(path));
  
  if (isPublicPath) {
    next();
  } else {
    authenticateToken(req, res, next);
  }
});

// ✅ NEW - Authentication Routes

// Login endpoint
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    // Validate input
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { username, password } = req.body;
      logSecurity('LOGIN_ATTEMPT', { 
      username, 
      ip: req.ip, 
      userAgent: req.get('User-Agent') 
    });
    // Get credentials from environment variables
    const validUsername = process.env.ADMIN_USERNAME || 'admin';
    const validPasswordHash = process.env.ADMIN_PASSWORD_HASH;
    
    // If no hash is set, use default password (ONLY for development)
    // Require password hash to be set
if (!validPasswordHash) {
  console.error('❌ ADMIN_PASSWORD_HASH environment variable is required');
  return res.status(500).json({ error: 'Server configuration error' });
}

// Verify password with bcrypt
const isValidPassword = await bcrypt.compare(password, validPasswordHash);

if (username === validUsername && isValidPassword) {
  const token = jwt.sign(
    { username, userId: 1 }, 
    process.env.JWT_SECRET, 
    { expiresIn: '24h' }
  );
  
  return res.json({ 
    token, 
    user: { username, id: 1 } 
  });
}
     else {
      // Production: Use bcrypt to verify password
      const isValidPassword = await bcrypt.compare(password, validPasswordHash);
      
      if (username === validUsername && isValidPassword) {
        const token = jwt.sign(
  { username, userId: 1 }, 
  process.env.JWT_SECRET, 
  { expiresIn: '24h' }
);
        
        return res.json({ 
          token, 
          user: { username, id: 1 } 
        });
      }
    }
       logSecurity('LOGIN_SUCCESS', { 
        username, 
        ip: req.ip, 
        userAgent: req.get('User-Agent') 
      });
       logSecurity('LOGIN_FAILED', { 
      username, 
      ip: req.ip, 
      userAgent: req.get('User-Agent') 
    });
    // Invalid credentials
    res.status(401).json({ error: 'Invalid username or password' });
    
   } catch (error) {
    logger.error('Login Error', { 
      error: error.message, 
      username: req.body?.username, 
      ip: req.ip 
    });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Token verification endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ 
    valid: true, 
    user: req.user 
  });
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Health check endpoint (public)
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ 
      status: 'OK', 
      database: 'Connected',
      timestamp: result.rows[0].now,
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      database: 'Disconnected',
      error: error.message 
    });
  }
});

// ✅ PROTECTED - Car wash management endpoints

// GET /api/washes - Get all washes with filters
app.get('/api/washes', async (req, res) => {
  try {
    const { 
      status, 
      serviceType, 
      vehicleType, 
      limit = 50, 
      offset = 0 
    } = req.query;
    
    let query = 'SELECT * FROM washes WHERE 1=1';
    const params = [];
    let paramCount = 0;
    
    if (status) {
      query += ` AND status = $${++paramCount}`;
      params.push(status);
    }
    
    if (serviceType) {
      query += ` AND service_type = $${++paramCount}`;
      params.push(serviceType);
    }
    
    if (vehicleType) {
      query += ` AND vehicle_type = $${++paramCount}`;
      params.push(vehicleType);
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${++paramCount} OFFSET $${++paramCount}`;
    params.push(limit, offset);
    
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching washes:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/washes - Create new wash
app.post('/api/washes', async (req, res) => {
  try {
    // Validate input
    const { error } = washSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const {
      immatriculation,
      serviceType,
      vehicleType,
      price,
      photos = [],
      motoDetails
    } = req.body;

    // Calculate price if not provided
    const calculatedPrice = price || calculatePrice(serviceType, vehicleType);

    const query = `
      INSERT INTO washes (
        immatriculation, service_type, vehicle_type, price, photos,
        moto_brand, moto_model, moto_helmets
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;
    
    const values = [
      immatriculation,
      serviceType,
      vehicleType,
      calculatedPrice,
      JSON.stringify(photos),
      motoDetails?.brand || null,
      motoDetails?.model || null,
      motoDetails?.helmets || 0
    ];
    
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating wash:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/washes/:id - Update wash
app.put('/api/washes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, endTime, duration } = req.body;
    
    const query = `
      UPDATE washes 
      SET status = $1, end_time = $2, duration = $3, updated_at = CURRENT_TIMESTAMP
      WHERE id = $4
      RETURNING *
    `;
    
    const result = await pool.query(query, [status, endTime, duration, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wash not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating wash:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/washes/:id - Delete wash
app.delete('/api/washes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM washes WHERE id = $1 RETURNING *', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wash not found' });
    }
    
    res.json({ message: 'Wash deleted successfully', wash: result.rows[0] });
  } catch (error) {
    console.error('Error deleting wash:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/stats - Dashboard statistics
app.get('/api/stats', async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total_washes,
        COUNT(*) FILTER (WHERE status = 'en_cours') as ongoing_washes,
        COUNT(*) FILTER (WHERE status = 'termine') as completed_washes,
        COALESCE(SUM(price) FILTER (WHERE status = 'termine'), 0) as total_revenue,
        COALESCE(AVG(duration) FILTER (WHERE duration > 0), 0) as avg_duration
      FROM washes
      WHERE created_at >= CURRENT_DATE
    `);
    
    res.json(stats.rows[0]);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/analytics - Advanced analytics
app.get('/api/analytics', async (req, res) => {
  try {
    const analytics = {};
    
    // Revenue by service type
    const revenueByService = await pool.query(`
      SELECT service_type, SUM(price) as revenue, COUNT(*) as count
      FROM washes 
      WHERE status = 'termine' AND created_at >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY service_type
    `);
    analytics.revenueByService = revenueByService.rows;
    
    // Daily revenue trend
    const dailyRevenue = await pool.query(`
      SELECT DATE(created_at) as date, SUM(price) as revenue
      FROM washes 
      WHERE status = 'termine' AND created_at >= CURRENT_DATE - INTERVAL '7 days'
      GROUP BY DATE(created_at)
      ORDER BY date
    `);
    analytics.dailyRevenue = dailyRevenue.rows;
    
    res.json(analytics);
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET /api/insights - AI insights
app.get('/api/insights', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM ai_insights 
      WHERE is_active = true 
      ORDER BY 
        CASE impact 
          WHEN 'high' THEN 1 
          WHEN 'medium' THEN 2 
          WHEN 'low' THEN 3 
        END,
        created_at DESC
      LIMIT 10
    `);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching insights:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/upload - Upload photos to Cloudinary
app.post('/api/upload', upload.array('photos', 5), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }
    
    const fileInfos = req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      size: file.bytes, // ✅ Cloudinary uses 'bytes' instead of 'size'
      url: file.path, // ✅ Cloudinary URL (full HTTPS URL)
      publicId: file.public_id, // ✅ Store for future reference/deletion
      thumbnailUrl: cloudinary.url(file.public_id, {
        width: 200,
        height: 200,
        crop: 'fill',
        quality: 'auto:low'
      })
    }));
    
    res.json({
      message: 'Photos uploaded successfully to Cloudinary',
      files: fileInfos
    });
  } catch (error) {
    console.error('Error uploading photos:', error);
    res.status(500).json({ error: error.message });
  }
});
// ✅ NEW - DELETE /api/upload/:publicId - Delete photo from Cloudinary
app.delete('/api/upload/:publicId', authenticateToken, async (req, res) => {
  try {
    const { publicId } = req.params;
    
    // Delete from Cloudinary
    const result = await cloudinary.uploader.destroy(publicId);
    
    if (result.result === 'ok') {
      res.json({ 
        message: 'Photo deleted successfully from Cloudinary',
        publicId: publicId 
      });
    } else {
      res.status(404).json({ 
        error: 'Photo not found in Cloudinary',
        publicId: publicId 
      });
    }
  } catch (error) {
    console.error('Error deleting photo from Cloudinary:', error);
    res.status(500).json({ error: error.message });
  }
});
// Helper function to calculate price based on service and vehicle type
function calculatePrice(serviceType, vehicleType) {
  const basePrices = {
    'interieur': { voiture: 15, camion: 25, moto: 10, taxi: 18 },
    'exterieur': { voiture: 12, camion: 20, moto: 8, taxi: 15 },
    'complet': { voiture: 25, camion: 40, moto: 18, taxi: 30 },
    'lavage-ville': { voiture: 25, camion: 40, moto: 18, taxi: 30 },
    'complet-premium': { voiture: 45, camion: 65, moto: 35, taxi: 50 }
  };
  
  return basePrices[serviceType]?.[vehicleType] || 20;
}

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Server Error', { 
    error: err.message, 
    stack: err.stack, 
    url: req.url, 
    method: req.method, 
    ip: req.ip 
  });
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large (max 5MB)' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files (max 5)' });
    }
  }
  
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  logger.info('🚀 Server Ready', {
    port: PORT,
    environment: process.env.NODE_ENV,
    healthCheck: `http://localhost:${PORT}/api/health`,
    timestamp: new Date().toISOString()
  });
  
  // Security validation (keep the security checks but log them)
  if (!process.env.JWT_SECRET) {
    logger.error('❌ FATAL: JWT_SECRET environment variable is required');
    process.exit(1);
  }
  
  if (!process.env.ADMIN_PASSWORD_HASH) {
    logger.error('❌ FATAL: ADMIN_PASSWORD_HASH environment variable is required');
    process.exit(1);
  }
  
  if (!process.env.ADMIN_USERNAME) {
    logger.error('❌ FATAL: ADMIN_USERNAME environment variable is required');
    process.exit(1);
  }
  
  logger.info('✅ Security validation complete');
});