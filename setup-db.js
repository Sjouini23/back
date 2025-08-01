// setup-db.js - PostgreSQL Database Setup Script
const { Pool } = require('pg');
require('dotenv').config();

// Admin connection pool (for creating database and user)
const adminPool = new Pool({
  user: process.env.DB_ADMIN_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: 'postgres', // Default PostgreSQL database
  password: process.env.DB_ADMIN_PASSWORD || '',
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Application connection pool
const appPool = new Pool({
  user: process.env.DB_USER || 'carwash_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'carwash_db',
  password: process.env.DB_PASSWORD || 'carwash_password',
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Main database setup function
const setupDatabase = async () => {
  console.log('🚀 Setting up PostgreSQL database...\n');

  try {
    // 1. Verify admin connection
    console.log('1. Verifying admin connection...');
    await adminPool.query('SELECT NOW()');
    console.log('✅ Admin connection established');

    // 2. Create database user if it doesn't exist
    console.log('\n2. Creating database user...');
    const userName = process.env.DB_USER || 'carwash_user';
    const userPassword = process.env.DB_PASSWORD || 'carwash_password';
    
    try {
      await adminPool.query(`
        CREATE USER ${userName} WITH PASSWORD '${userPassword}'
      `);
      console.log(`✅ User '${userName}' created`);
    } catch (error) {
      if (error.code === '42710') { // User already exists
        console.log(`ℹ️  User '${userName}' already exists`);
      } else {
        throw error;
      }
    }

    // 3. Create database if it doesn't exist
    console.log('\n3. Creating database...');
    const dbName = process.env.DB_NAME || 'carwash_db';
    
    try {
      await adminPool.query(`CREATE DATABASE ${dbName} OWNER ${userName}`);
      console.log(`✅ Database '${dbName}' created`);
    } catch (error) {
      if (error.code === '42P04') { // Database already exists
        console.log(`ℹ️  Database '${dbName}' already exists`);
      } else {
        throw error;
      }
    }

    // 4. Grant privileges
    console.log('\n4. Granting privileges...');
    await adminPool.query(`
      GRANT ALL PRIVILEGES ON DATABASE ${dbName} TO ${userName}
    `);
    await adminPool.query(`
      ALTER USER ${userName} CREATEDB
    `);
    console.log('✅ Privileges granted');

    // 5. Verify application connection
    console.log('\n5. Verifying application connection...');
    await appPool.query('SELECT NOW()');
    console.log('✅ Application connection established');

    // 6. Create PostgreSQL extensions
    console.log('\n6. Installing PostgreSQL extensions...');
    try {
      await appPool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
      console.log('✅ uuid-ossp extension installed');
    } catch (error) {
      console.log('⚠️  uuid-ossp extension not available (using gen_random_uuid())');
    }

    try {
      await appPool.query('CREATE EXTENSION IF NOT EXISTS "pg_stat_statements"');
      console.log('✅ pg_stat_statements extension installed');
    } catch (error) {
      console.log('⚠️  pg_stat_statements extension not available');
    }

    // 7. Initialize database tables
    console.log('\n7. Initializing tables...');
    
    // Create washes table
    await appPool.query(`
      CREATE TABLE IF NOT EXISTS washes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        immatriculation VARCHAR(20) NOT NULL,
        service_type VARCHAR(20) NOT NULL CHECK (service_type IN ('interieur', 'exterieur', 'complet')),
        vehicle_type VARCHAR(20) NOT NULL CHECK (vehicle_type IN ('voiture', 'camion', 'moto')),
        price DECIMAL(10,2) NOT NULL,
        start_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP WITH TIME ZONE,
        duration INTEGER,
        status VARCHAR(20) DEFAULT 'en_cours' CHECK (status IN ('en_cours', 'termine')),
        photos JSONB DEFAULT '[]'::jsonb,
        moto_brand VARCHAR(50),
        moto_model VARCHAR(50),
        moto_helmets INTEGER DEFAULT 0 CHECK (moto_helmets >= 0 AND moto_helmets <= 4),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Table "washes" created');

    // Create indexes for performance
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_washes_status ON washes(status)',
      'CREATE INDEX IF NOT EXISTS idx_washes_start_time ON washes(start_time)',
      'CREATE INDEX IF NOT EXISTS idx_washes_immatriculation ON washes(immatriculation)',
      'CREATE INDEX IF NOT EXISTS idx_washes_vehicle_type ON washes(vehicle_type)',
      'CREATE INDEX IF NOT EXISTS idx_washes_service_type ON washes(service_type)'
    ];

    for (const indexQuery of indexes) {
      await appPool.query(indexQuery);
    }
    console.log('✅ Indexes created');

    // Create AI insights table
    await appPool.query(`
      CREATE TABLE IF NOT EXISTS ai_insights (
        id SERIAL PRIMARY KEY,
        type VARCHAR(20) NOT NULL CHECK (type IN ('suggestion', 'warning', 'opportunity')),
        title VARCHAR(200) NOT NULL,
        description TEXT NOT NULL,
        impact VARCHAR(10) NOT NULL CHECK (impact IN ('high', 'medium', 'low')),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true
      )
    `);
    console.log('✅ Table "ai_insights" created');

    // Create trigger function for automatic updated_at
    await appPool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ language 'plpgsql'
    `);

    // Create trigger for updated_at
    await appPool.query(`
      DROP TRIGGER IF EXISTS update_washes_updated_at ON washes;
      CREATE TRIGGER update_washes_updated_at
        BEFORE UPDATE ON washes
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column()
    `);
    console.log('✅ Triggers created');

    // 8. Insert demo data
    console.log('\n8. Inserting demo data...');
    
    // Check if AI insights already exist
    const { rows } = await appPool.query('SELECT COUNT(*) as count FROM ai_insights');
    if (parseInt(rows[0].count) === 0) {
      await appPool.query(`
        INSERT INTO ai_insights (type, title, description, impact) VALUES
        ('opportunity', 'Peak activity detected', 'Afternoons 2-5 PM generate 40% more revenue. Consider a morning promotion.', 'high'),
        ('suggestion', 'Popular motorcycle service', 'Motorcycles represent 25% of washes. Propose a special motorcycle equipment package.', 'medium'),
        ('warning', 'Long service time', 'Complete service takes 15% longer than expected. Optimize the process.', 'medium'),
        ('opportunity', 'Customer loyalty', 'Create a loyalty program for regular customers with 10% discount after 5 washes.', 'high'),
        ('suggestion', 'Schedule optimization', 'Better distribute time slots to avoid waiting periods longer than 15 minutes.', 'medium')
      `);
      console.log('✅ Demo data inserted');
    } else {
      console.log('ℹ️  Demo data already exists');
    }

    // 9. Functionality tests
    console.log('\n9. Running functionality tests...');
    
    // Test insert
    const testWash = await appPool.query(`
      INSERT INTO washes (immatriculation, service_type, vehicle_type, price) 
      VALUES ('TEST123', 'complet', 'voiture', 30.00) 
      RETURNING id
    `);
    
    // Test select
    await appPool.query('SELECT * FROM washes WHERE id = $1', [testWash.rows[0].id]);
    
    // Test delete
    await appPool.query('DELETE FROM washes WHERE id = $1', [testWash.rows[0].id]);
    
    console.log('✅ Functionality tests passed');

    console.log('\n🎉 Setup completed successfully!');
    console.log('\n📋 Connection information:');
    console.log(`   Host: ${process.env.DB_HOST || 'localhost'}`);
    console.log(`   Port: ${process.env.DB_PORT || 5432}`);
    console.log(`   Database: ${process.env.DB_NAME || 'carwash_db'}`);
    console.log(`   Username: ${process.env.DB_USER || 'carwash_user'}`);
    console.log(`   Connection string: postgresql://${process.env.DB_USER || 'carwash_user'}:${process.env.DB_PASSWORD || '[password]'}@${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME || 'carwash_db'}`);
    
    console.log('\n🚀 Next steps:');
    console.log('   1. npm run dev (start development server)');
    console.log('   2. Access API: http://localhost:3001/api/health');

  } catch (error) {
    console.error('\n❌ Setup error:', error.message);
    if (error.code) {
      console.error(`   PostgreSQL error code: ${error.code}`);
    }
    process.exit(1);
  } finally {
    await adminPool.end();
    await appPool.end();
  }
};

// Database diagnostic function
const diagnosticDatabase = async () => {
  console.log('🔍 Database diagnostic...\n');

  try {
    // Table size information
    const result = await appPool.query(`
      SELECT 
        schemaname,
        tablename,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
      FROM pg_tables 
      WHERE schemaname = 'public' 
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
    `);

    console.log('📊 Tables and sizes:');
    result.rows.forEach(row => {
      console.log(`   ${row.tablename}: ${row.size}`);
    });

    // Statistics
    const statsResult = await appPool.query(`
      SELECT 
        'washes' as table_name,
        COUNT(*) as total_records,
        COUNT(*) FILTER (WHERE status = 'en_cours') as ongoing,
        COUNT(*) FILTER (WHERE status = 'termine') as completed
      FROM washes
      UNION ALL
      SELECT 
        'ai_insights' as table_name,
        COUNT(*) as total_records,
        COUNT(*) FILTER (WHERE is_active = true) as active,
        COUNT(*) FILTER (WHERE is_active = false) as inactive
      FROM ai_insights
    `);

    console.log('\n📈 Statistics:');
    statsResult.rows.forEach(row => {
      console.log(`   ${row.table_name}: ${row.total_records} records`);
      if (row.table_name === 'washes') {
        console.log(`     - Ongoing: ${row.ongoing}`);
        console.log(`     - Completed: ${row.completed}`);
      } else if (row.table_name === 'ai_insights') {
        console.log(`     - Active: ${row.active}`);
        console.log(`     - Inactive: ${row.inactive}`);
      }
    });

  } catch (error) {
    console.error('❌ Diagnostic error:', error.message);
  } finally {
    await appPool.end();
  }
};

// Database cleanup function
const cleanDatabase = async () => {
  console.log('🧹 Cleaning database...\n');

  try {
    // Delete test washes
    const result = await appPool.query("DELETE FROM washes WHERE immatriculation LIKE 'TEST%'");
    console.log(`✅ ${result.rowCount} test washes deleted`);

    // Optimize database
    await appPool.query('VACUUM ANALYZE');
    console.log('✅ Database optimized');

  } catch (error) {
    console.error('❌ Cleanup error:', error.message);
  } finally {
    await appPool.end();
  }
};

// Command line interface
if (require.main === module) {
  const command = process.argv[2];
  
  switch (command) {
    case 'setup':
      setupDatabase();
      break;
    case 'diagnostic':
      diagnosticDatabase();
      break;
    case 'clean':
      cleanDatabase();
      break;
    default:
      console.log('📖 Usage: node setup-db.js [setup|diagnostic|clean]');
      console.log('   setup     - Complete database setup');
      console.log('   diagnostic - Display database information');
      console.log('   clean     - Clean test data');
      break;
  }
}

module.exports = {
  setupDatabase,
  diagnosticDatabase,
  cleanDatabase
};