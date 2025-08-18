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
app.set('trust proxy', true);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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

// ✅ FIXED - UNCOMMENTED CORS
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman, etc.)
    if (!origin) return callback(null, true);

    const allowedOrigins = getCorsOrigins();

    // Check if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    // Allow Vercel preview domains
    if (origin.match(/^https:\/\/lavage-v1.*\.vercel\.app$/)) {
      return callback(null, true);
    }

    // Allow if CORS_ALLOW_VERCEL_PREVIEWS is true
    if (process.env.CORS_ALLOW_VERCEL_PREVIEWS === 'true' &&
        origin.includes('.vercel.app')) {
      return callback(null, true);
    }

    return callback(null, true); // Allow all for now to test
  },
  credentials: true,
  methods: ['GET', 'PATCH' ,'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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

// ✅ FIXED - Updated Joi Schema with all fields
const washSchema = Joi.object({
  immatriculation: Joi.string().pattern(/^[A-Z0-9\-\s]{3,15}$/i).required(),
  serviceType: Joi.string().valid('interieur', 'exterieur', 'complet', 'lavage-ville', 'complet-premium').required(),
  vehicleType: Joi.string().valid('voiture', 'camion', 'moto', 'taxi').required(),
  price: Joi.number().min(0).optional(),
  photos: Joi.array().items(Joi.string()).optional(),
  motoDetails: Joi.object().optional(),
  // ✅ ADD MISSING FIELDS:
  price_adjustment: Joi.number().optional(),
  vehicle_brand: Joi.string().allow('').optional(),
  vehicle_model: Joi.string().allow('').optional(),
  vehicle_color: Joi.string().allow('').optional(),
  staff: Joi.array().items(Joi.string()).optional(),
  phone: Joi.string().allow('').optional(),
  notes: Joi.string().allow('').optional()
}).options({ allowUnknown: true }); // ✅ Allow extra fields

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

    // Check if password hash is configured
    if (!validPasswordHash) {
      console.error('❌ ADMIN_PASSWORD_HASH environment variable is required');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // ✅ FIXED: Single, clear authentication logic
    const isValidPassword = await bcrypt.compare(password, validPasswordHash);

    if (username === validUsername && isValidPassword) {
      // ✅ SUCCESS: Generate token
      const token = jwt.sign(
        { username, userId: 1 },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );

      logSecurity('LOGIN_SUCCESS', {
        username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.json({
        token,
        user: { username, id: 1 }
      });
    } else {
      // ✅ FAILURE: Invalid credentials
      logSecurity('LOGIN_FAILED', {
        username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return res.status(401).json({ error: 'Invalid username or password' });
    }

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

// ✅ ADDED - Validation middleware
const validateServiceData = (req, res, next) => {
  try {
    const data = req.body;
    
    // ✅ ENSURE NUMERIC FIELDS ARE PROPER NUMBERS
    if (data.price !== undefined) {
      const price = parseFloat(data.price);
      data.price = isNaN(price) || !isFinite(price) ? 0 : Math.round(price * 100) / 100;
    }
    
    if (data.price_adjustment !== undefined) {
      const adj = parseFloat(data.price_adjustment);
      data.price_adjustment = isNaN(adj) || !isFinite(adj) ? 0 : Math.round(adj * 100) / 100;
    }
    
    // ✅ ENSURE REQUIRED STRING FIELDS
    data.immatriculation = (data.immatriculation || '').toString().trim();
    data.serviceType = data.serviceType || 'lavage-ville';
    data.vehicleType = data.vehicleType || 'voiture';
    
    // ✅ ENSURE ARRAYS ARE ARRAYS
    if (data.photos && !Array.isArray(data.photos)) {
      data.photos = [];
    }
    
    if (data.staff && !Array.isArray(data.staff)) {
      data.staff = data.staff ? [data.staff] : [];
    }
    
    // ✅ ADD SAFE DEFAULTS
    data.vehicle_brand = data.vehicle_brand || data.vehicleBrand || '';
    data.vehicle_model = data.vehicle_model || data.vehicleModel || '';
    data.vehicle_color = data.vehicle_color || data.vehicleColor || '';
    data.phone = data.phone || '';
    data.notes = data.notes || '';
    
    req.body = data;
    next();
  } catch (error) {
    console.error('Data validation error:', error);
    res.status(400).json({ error: 'Invalid data format' });
  }
};

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

// POST /api/washes - Create new wash - ✅ ADDED VALIDATION MIDDLEWARE
// Replace the POST /api/washes endpoint in server.js (around line 470-520):

app.post('/api/washes', validateServiceData, async (req, res) => {
  try {
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
      vehicle_brand,
      vehicle_model,
      vehicle_color,
      staff = [],
      phone,
      notes,
      price_adjustment,
      motoDetails,
      date,        // 🚨 NEW: Accept date from frontend
      createdAt    // 🚨 NEW: Accept createdAt from frontend
    } = req.body;

    const calculatedPrice = price || calculatePrice(serviceType, vehicleType);
    
    // 🚨 FIX: Use custom date if provided, otherwise current time
    const customDate = date ? new Date(date + 'T' + new Date().toTimeString().split(' ')[0]) : new Date();
    const customCreatedAt = createdAt ? new Date(createdAt) : customDate;
    const now = new Date().toISOString(); // Only for updated_at

    console.log('🚀 Creating service with custom date:', {
      received_date: date,
      customDate: customDate.toISOString(),
      immatriculation: immatriculation
    });

    // ✅ FIXED: Match columns with values and include timer fields
    const query = `
      INSERT INTO washes (
        immatriculation, service_type, vehicle_type, price, photos,
        vehicle_brand, vehicle_model, vehicle_color, staff, phone, notes,
        price_adjustment, moto_brand, moto_model, moto_helmets,
        time_started, is_active, status, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
      RETURNING *
    `;

    const values = [
      immatriculation,
      serviceType,
      vehicleType,
      calculatedPrice,
      JSON.stringify(photos),
      vehicle_brand || '',
      vehicle_model || '',
      vehicle_color || '',
      JSON.stringify(staff),
      phone || '',
      notes || '',
      price_adjustment || 0,
      motoDetails?.brand || null,
      motoDetails?.model || null,
      motoDetails?.helmets || 0,
      // 🚨 FIXED TIMER FIELDS - Use custom date
      now,      // time_started (custom date!)
      true,                          // is_active
      'active',                      // status
      customCreatedAt.toISOString(), // created_at (custom date!)
      now                           // updated_at (always current time)
    ];

    const result = await pool.query(query, values);
    
    console.log('✅ Service created with custom date:', {
      id: result.rows[0].id,
      immatriculation: result.rows[0].immatriculation,
      created_at: result.rows[0].created_at,
      time_started: result.rows[0].time_started
    });
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating wash:', error);
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
// ✅ COMPLETE PUT endpoint for editing services
app.put('/api/washes/:id', validateServiceData, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = washSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const {
      immatriculation,
      serviceType,
      vehicleType,
      price,
      price_adjustment,
      vehicle_brand,
      vehicle_model,
      vehicle_color,
      staff,
      phone,
      notes,
      photos,
      status,
      motoDetails
    } = req.body;

    const query = `
      UPDATE washes
      SET immatriculation = $1, service_type = $2, vehicle_type = $3, price = $4,
          price_adjustment = $5, vehicle_brand = $6, vehicle_model = $7, 
          vehicle_color = $8, staff = $9, phone = $10, notes = $11, 
          photos = $12, status = $13, moto_brand = $14, moto_model = $15,
          moto_helmets = $16, updated_at = CURRENT_TIMESTAMP
      WHERE id = $17
      RETURNING *
    `;

    const values = [
      immatriculation,
      serviceType, 
      vehicleType,
      price || 0,
      price_adjustment || 0,
      vehicle_brand || '',
      vehicle_model || '',
      vehicle_color || '',
      JSON.stringify(staff || []),
      phone || '',
      notes || '',
      JSON.stringify(photos || []),
      status || 'pending',
      motoDetails?.brand || null,
      motoDetails?.model || null,
      motoDetails?.helmets || 0,
      id
    ];
// Add this NEW endpoint to server.js after the existing PUT endpoint (around line 400):

// ✅ NEW - FINISH TIMER endpoint - THIS WAS MISSING!
// ✅ COMPLETE PUT endpoint for editing services
app.put('/api/washes/:id', validateServiceData, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = washSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const {
      immatriculation,
      serviceType,
      vehicleType,
      price,
      price_adjustment,
      vehicle_brand,
      vehicle_model,
      vehicle_color,
      staff,
      phone,
      notes,
      photos,
      status,
      motoDetails
    } = req.body;

    const query = `
      UPDATE washes
      SET immatriculation = $1, service_type = $2, vehicle_type = $3, price = $4,
          price_adjustment = $5, vehicle_brand = $6, vehicle_model = $7, 
          vehicle_color = $8, staff = $9, phone = $10, notes = $11, 
          photos = $12, status = $13, moto_brand = $14, moto_model = $15,
          moto_helmets = $16, updated_at = CURRENT_TIMESTAMP
      WHERE id = $17
      RETURNING *
    `;

    const values = [
      immatriculation,
      serviceType, 
      vehicleType,
      price || 0,
      price_adjustment || 0,
      vehicle_brand || '',
      vehicle_model || '',
      vehicle_color || '',
      JSON.stringify(staff || []),
      phone || '',
      notes || '',
      JSON.stringify(photos || []),
      status || 'pending',
      motoDetails?.brand || null,
      motoDetails?.model || null,
      motoDetails?.helmets || 0,
      id
    ];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wash not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating wash:', error);
    res.status(500).json({ error: error.message });
  }
});

// ✅ SEPARATE FINISH endpoint (AFTER PUT is complete)
app.patch('/api/washes/:id/finish', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    
    // Get the current service to calculate duration
    const currentService = await pool.query('SELECT * FROM washes WHERE id = $1', [id]);
    
    if (currentService.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }
    
    const service = currentService.rows[0];
    let totalDuration = 0;
    
    // Calculate duration if service has a start time
    if (service.time_started) {
      const startTime = new Date(service.time_started);
      const endTime = new Date(now);
      totalDuration = Math.floor((endTime - startTime) / 1000); // Duration in seconds
    }
    
    // Update the service to mark it as finished
    const query = `
      UPDATE washes 
      SET 
        time_finished = $1,
        total_duration = $2,
        is_active = false,
        status = 'completed',
        updated_at = $1
      WHERE id = $3
      RETURNING *
    `;
    
    const values = [now, totalDuration, id];
    const result = await pool.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }
    
    logger.info('Timer finished', {
      serviceId: id,
      duration: totalDuration,
      durationMinutes: Math.floor(totalDuration / 60)
    });
    
    res.json({
      message: 'Timer stopped successfully',
      service: result.rows[0],
      duration: totalDuration,
      durationMinutes: Math.floor(totalDuration / 60)
    });
    
  } catch (error) {
    logger.error('Error finishing timer:', error);
    res.status(500).json({ error: error.message });
  }
});
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Wash not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating wash:', error);
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
