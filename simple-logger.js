// simple-logger.js - Basic Logging for Production
const winston = require('winston');
const fs = require('fs');

// Create logs directory
if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

// Simple logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
      if (Object.keys(meta).length > 0) {
        log += ` | ${JSON.stringify(meta)}`;
      }
      return log;
    })
  ),
  transports: [
    // Errors only
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 3
    }),
    // All logs
    new winston.transports.File({ 
      filename: 'logs/app.log',
      maxsize: 5242880, // 5MB
      maxFiles: 3
    }),
    // Console for development
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// Security events logger
const logSecurity = (event, details) => {
  logger.warn(`SECURITY: ${event}`, details);
};

// Performance logger
const logSlow = (operation, duration, details) => {
  if (duration > 1000) {
    logger.warn(`SLOW: ${operation} took ${duration}ms`, details);
  }
};

module.exports = { logger, logSecurity, logSlow };