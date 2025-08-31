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
const helmet = require('helmet');

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
  max: 900, // limit each IP to 100 requests per windowMs
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
const getCorsOrigins = () => {
  const envOrigins = process.env.CORS_ORIGINS ?
    process.env.CORS_ORIGINS.split(',').map(origin => origin.trim()) : [];

  const defaultOrigins = [
    'http://localhost:3000',
    'http://localhost:3001',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3001'
  ];

  return [...new Set([...defaultOrigins, ...envOrigins])];
};

const allowedOrigins = getCorsOrigins();
console.log('🔐 CORS allowed origins:', allowedOrigins);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    const allowedOrigins = getCorsOrigins();

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    if (origin.match(/^https:\/\/lavage-v1.*\.vercel\.app$/)) {
      return callback(null, true);
    }

    if (process.env.CORS_ALLOW_VERCEL_PREVIEWS === 'true' &&
        origin.includes('.vercel.app')) {
      return callback(null, true);
    }

    return callback(null, true); // Allow all for now to test
  },
  credentials: true,
  methods: ['GET', 'PATCH', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('📁 Created uploads directory');
}

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
    folder: 'jouini-carwash',
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
    fileSize: 10 * 1024 * 1024, // 10MB max
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
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// ✅ JWT Authentication Middleware
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

// ✅ Input validation schemas
const loginSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  password: Joi.string().min(3).max(100).required()
});

const washSchema = Joi.object({
  immatriculation: Joi.string().pattern(/^[A-Z0-9\-\s]{3,15}$/i).required(),
  serviceType: Joi.string().valid('interieur', 'exterieur', 'complet', 'lavage-ville', 'complet-premium').required(),
  vehicleType: Joi.string().valid('voiture', 'camion', 'moto', 'taxi').required(),
  price: Joi.number().min(0).optional(),
  photos: Joi.array().items(Joi.string()).optional(),
  motoDetails: Joi.object().optional(),
  price_adjustment: Joi.number().optional(),
  vehicle_brand: Joi.string().allow('').optional(),
  vehicle_model: Joi.string().allow('').optional(),
  vehicle_color: Joi.string().allow('').optional(),
  staff: Joi.array().items(Joi.string()).optional(),
  phone: Joi.string().allow('').optional(),
  notes: Joi.string().allow('').optional()
}).options({ allowUnknown: true });

// ✅ Protect API routes with authentication
app.use('/api', (req, res, next) => {
  const publicPaths = ['/auth/login', '/auth/verify', '/health'];
  const isPublicPath = publicPaths.some(path => req.path.startsWith(path));

  if (isPublicPath) {
    next();
  } else {
    authenticateToken(req, res, next);
  }
});

// ✅ Authentication Routes
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
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
    
    const validUsername = process.env.ADMIN_USERNAME || 'admin';
    const validPasswordHash = process.env.ADMIN_PASSWORD_HASH;

    if (!validPasswordHash) {
      console.error('❌ ADMIN_PASSWORD_HASH environment variable is required');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    const isValidPassword = await bcrypt.compare(password, validPasswordHash);

    if (username === validUsername && isValidPassword) {
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

app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user
  });
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

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

// ✅ Validation middleware
const validateServiceData = (req, res, next) => {
  try {
    const data = req.body;
    
    if (data.price !== undefined) {
      const price = parseFloat(data.price);
      data.price = isNaN(price) || !isFinite(price) ? 0 : Math.round(price * 100) / 100;
    }
    
    if (data.price_adjustment !== undefined) {
      const adj = parseFloat(data.price_adjustment);
      data.price_adjustment = isNaN(adj) || !isFinite(adj) ? 0 : Math.round(adj * 100) / 100;
    }
    
    data.immatriculation = (data.immatriculation || '').toString().trim();
    data.serviceType = data.serviceType || 'lavage-ville';
    data.vehicleType = data.vehicleType || 'voiture';
    
    if (data.photos && !Array.isArray(data.photos)) {
      data.photos = [];
    }
    
    if (data.staff && !Array.isArray(data.staff)) {
      data.staff = data.staff ? [data.staff] : [];
    }
    
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
      limit = 500,
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
      date,
      createdAt
    } = req.body;

    // ✅ Ensure proper types
    const calculatedPrice = parseFloat(price) || calculatePrice(serviceType, vehicleType);
    const customDate = date ? new Date(date + 'T' + new Date().toTimeString().split(' ')[0]) : new Date();
    const customCreatedAt = createdAt ? new Date(createdAt) : customDate;
    const now = new Date().toISOString();

    // ✅ Validate required fields
    if (!immatriculation || immatriculation.trim() === '') {
      return res.status(400).json({ error: 'License plate is required' });
    }

    console.log('🚀 Creating service:', {
      immatriculation: immatriculation,
      serviceType: serviceType,
      vehicleType: vehicleType
    });

    // ✅ Use correct column names (start_time, not time_started)
    const query = `
      INSERT INTO washes (
        immatriculation, service_type, vehicle_type, price, photos,
        vehicle_brand, vehicle_model, vehicle_color, staff, phone, notes,
        price_adjustment, moto_brand, moto_model, moto_helmets,
        start_time, is_active, status, created_at, updated_at
      ) VALUES ($1, $2, $3, $4::decimal, $5::jsonb, $6, $7, $8, $9::jsonb, $10, $11, $12::decimal, $13, $14, $15::integer, $16::timestamp, $17::boolean, $18, $19::timestamp, $20::timestamp)
      RETURNING *
    `;

    const values = [
      String(immatriculation).trim(),           // $1
      String(serviceType),                      // $2  
      String(vehicleType),                      // $3
      calculatedPrice,                          // $4
      JSON.stringify(photos || []),             // $5
      String(vehicle_brand || ''),              // $6
      String(vehicle_model || ''),              // $7
      String(vehicle_color || ''),              // $8
      JSON.stringify(staff || []),              // $9
      String(phone || ''),                      // $10
      String(notes || ''),                      // $11
      parseFloat(price_adjustment) || 0,        // $12
      motoDetails?.brand || null,               // $13
      motoDetails?.model || null,               // $14
      parseInt(motoDetails?.helmets) || 0,      // $15
      now,                                      // $16
      true,                                     // $17
      'active',                                 // $18
      customCreatedAt.toISOString(),           // $19
      now                                       // $20
    ];

    const result = await pool.query(query, values);
    
    console.log('✅ Service created successfully:', {
      id: result.rows[0].id,
      immatriculation: result.rows[0].immatriculation
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

// ✅ PUT endpoint for editing services
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

    // ✅ Ensure proper types and handle nulls
    const query = `
      UPDATE washes
      SET immatriculation = $1, service_type = $2, vehicle_type = $3, price = $4::decimal,
          price_adjustment = $5::decimal, vehicle_brand = $6, vehicle_model = $7, 
          vehicle_color = $8, staff = $9::jsonb, phone = $10, notes = $11, 
          photos = $12::jsonb, status = $13, moto_brand = $14, moto_model = $15,
          moto_helmets = $16::integer, updated_at = CURRENT_TIMESTAMP
      WHERE id = $17
      RETURNING *
    `;

    const values = [
      String(immatriculation || '').trim(),
      String(serviceType || 'lavage-ville'), 
      String(vehicleType || 'voiture'),
      parseFloat(price) || 0,
      parseFloat(price_adjustment) || 0,
      String(vehicle_brand || ''),
      String(vehicle_model || ''),
      String(vehicle_color || ''),
      JSON.stringify(staff || []),
      String(phone || ''),
      String(notes || ''),
      JSON.stringify(photos || []),
      String(status || 'pending'),
      motoDetails?.brand || null,
      motoDetails?.model || null,
      parseInt(motoDetails?.helmets) || 0,
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

// ✅ FIXED - FINISH TIMER endpoint 
app.patch('/api/washes/:id/finish', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();
    
    console.log('🎯 FINISH ENDPOINT HIT:', id);
    
    // Get the current service to calculate duration
    const currentService = await pool.query('SELECT * FROM washes WHERE id = $1', [id]);
    
    if (currentService.rows.length === 0) {
      return res.status(404).json({ error: 'Service not found' });
    }
    
    const service = currentService.rows[0];
    let totalDuration = 0;
    
    // ✅ Use correct column name (start_time)
    if (service.start_time) {
      const startTime = new Date(service.start_time);
      const endTime = new Date(now);
      totalDuration = Math.floor((endTime - startTime) / 1000);
    }
    
    // ✅ FIXED: Use CURRENT_TIMESTAMP for updated_at instead of reusing $1
    const query = `
      UPDATE washes 
      SET 
        end_time = $1::timestamp,
        duration = $2::integer,
        is_active = $3::boolean,
        status = $4,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
      RETURNING *
    `;
    
    const values = [now, totalDuration, false, 'completed', id];
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

    const revenueByService = await pool.query(`
      SELECT service_type, SUM(price) as revenue, COUNT(*) as count
      FROM washes
      WHERE status = 'termine' AND created_at >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY service_type
    `);
    analytics.revenueByService = revenueByService.rows;

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
// 🔷 TV DISPLAY ENDPOINTS - SUPPORT MULTIPLE SERVICES
// FIXED Server TV Endpoints - server.js (TV Display section)

// 🔥 FIXED TV DISPLAY ENDPOINTS - NO REVENUE EXPOSURE
app.get('/api/tv/current-services', authenticateToken, async (req, res) => {
  try {
    // 🔥 FIX: Remove price from TV endpoint for security
    // 🔥 FIX: Use consistent status values
    const result = await pool.query(`
      SELECT 
        id, 
        immatriculation, 
        vehicle_brand, 
        vehicle_model, 
        vehicle_color, 
        service_type, 
        staff, 
        start_time,
        created_at,
        status
      FROM washes 
      WHERE (status = 'active' OR status = 'en_cours') 
        AND is_active = true 
        AND DATE(created_at) = CURRENT_DATE
        AND start_time IS NOT NULL
      ORDER BY start_time ASC 
      LIMIT 8
    `);
    
    // 🔥 FIX: Add proper data validation and formatting
    const services = result.rows.map(service => ({
      id: service.id,
      immatriculation: service.immatriculation || 'N/A',
      vehicle_brand: service.vehicle_brand || '',
      vehicle_model: service.vehicle_model || '',
      vehicle_color: service.vehicle_color || '',
      service_type: service.service_type || 'lavage-ville',
      staff: Array.isArray(service.staff) ? service.staff : [],
      start_time: service.start_time,
      created_at: service.created_at,
      status: service.status
    }));
    
    console.log(`📺 TV Display: Serving ${services.length} active services`);
    res.json(services);
    
  } catch (error) {
    console.error('❌ Error fetching TV current services:', error);
    res.status(500).json({ 
      error: 'Unable to fetch current services',
      services: [] // Return empty array on error
    });
  }
});

// 🔥 FIXED TV QUEUE ENDPOINT - Better filtering
app.get('/api/tv/queue', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, 
        immatriculation, 
        vehicle_brand, 
        vehicle_model, 
        vehicle_color, 
        service_type, 
        staff, 
        created_at
      FROM washes 
      WHERE status = 'pending' 
        AND is_active = true
        AND DATE(created_at) = CURRENT_DATE
      ORDER BY created_at ASC 
      LIMIT 10
    `);
    
    const queue = result.rows.map(service => ({
      id: service.id,
      immatriculation: service.immatriculation || 'N/A',
      vehicle_brand: service.vehicle_brand || '',
      vehicle_model: service.vehicle_model || '',
      vehicle_color: service.vehicle_color || '',
      service_type: service.service_type || 'lavage-ville',
      staff: Array.isArray(service.staff) ? service.staff : [],
      created_at: service.created_at,
      position: result.rows.indexOf(service) + 1
    }));
    
    console.log(`📺 TV Queue: Serving ${queue.length} pending services`);
    res.json(queue);
    
  } catch (error) {
    console.error('❌ Error fetching TV queue:', error);
    res.status(500).json({ 
      error: 'Unable to fetch queue',
      queue: []
    });
  }
});

// 🔥 NEW: TV STATS ENDPOINT - Public safe stats only
app.get('/api/tv/stats', authenticateToken, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE status IN ('active', 'en_cours') AND is_active = true AND DATE(created_at) = CURRENT_DATE) as active_services,
        COUNT(*) FILTER (WHERE status = 'pending' AND DATE(created_at) = CURRENT_DATE) as pending_services,
        COUNT(*) FILTER (WHERE status IN ('completed', 'termine') AND DATE(created_at) = CURRENT_DATE) as completed_today,
        COUNT(*) FILTER (WHERE DATE(created_at) = CURRENT_DATE) as total_today
      FROM washes
      WHERE created_at >= CURRENT_DATE
    `);

    const publicStats = {
      active_services: parseInt(stats.rows[0]?.active_services || 0),
      pending_services: parseInt(stats.rows[0]?.pending_services || 0),
      completed_today: parseInt(stats.rows[0]?.completed_today || 0),
      total_today: parseInt(stats.rows[0]?.total_today || 0),
      // 🔥 NO REVENUE DATA FOR TV DISPLAY
      timestamp: new Date().toISOString()
    };

    console.log('📺 TV Stats served:', publicStats);
    res.json(publicStats);
    
  } catch (error) {
    console.error('❌ Error fetching TV stats:', error);
    res.status(500).json({ 
      error: 'Unable to fetch stats',
      active_services: 0,
      pending_services: 0,
      completed_today: 0,
      total_today: 0
    });
  }
});

// 🔥 FIXED MAIN STATS ENDPOINT - Keep revenue for internal dashboard only
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    // This endpoint keeps revenue data for internal dashboard use only
    const stats = await pool.query(`
      SELECT
        COUNT(*) as total_washes,
        COUNT(*) FILTER (WHERE status IN ('active', 'en_cours') AND is_active = true) as ongoing_washes,
        COUNT(*) FILTER (WHERE status IN ('completed', 'termine')) as completed_washes,
        COALESCE(SUM(price) FILTER (WHERE status IN ('completed', 'termine')), 0) as total_revenue,
        COALESCE(AVG(duration) FILTER (WHERE duration > 0), 0) as avg_duration
      FROM washes
      WHERE created_at >= CURRENT_DATE
    `);

    res.json({
      total_washes: parseInt(stats.rows[0]?.total_washes || 0),
      ongoing_washes: parseInt(stats.rows[0]?.ongoing_washes || 0),
      completed_washes: parseInt(stats.rows[0]?.completed_washes || 0),
      total_revenue: parseFloat(stats.rows[0]?.total_revenue || 0),
      avg_duration: parseFloat(stats.rows[0]?.avg_duration || 0)
    });
    
  } catch (error) {
    console.error('❌ Error fetching internal stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// 🔥 HELPER: Status standardization middleware
const standardizeStatus = (req, res, next) => {
  if (req.body.status) {
    // Convert various status formats to standard ones
    const statusMap = {
      'en_cours': 'active',
      'en cours': 'active',
      'actif': 'active',
      'terminé': 'completed',
      'termine': 'completed',
      'fini': 'completed',
      'en_attente': 'pending',
      'attente': 'pending'
    };
    
    const normalizedStatus = statusMap[req.body.status.toLowerCase()] || req.body.status;
    req.body.status = normalizedStatus;
  }
  next();
};

// Apply status standardization to relevant routes
app.use('/api/washes', standardizeStatus);

// 🔥 ENHANCED ERROR HANDLING for TV endpoints
app.use('/api/tv/*', (err, req, res, next) => {
  console.error('TV Endpoint Error:', err);
  res.status(500).json({
    error: 'TV service temporarily unavailable',
    timestamp: new Date().toISOString()
  });
});

// DELETE /api/upload/:publicId - Delete photo from Cloudinary
app.delete('/api/upload/:publicId', authenticateToken, async (req, res) => {
  try {
    const { publicId } = req.params;

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

  // Security validation
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
