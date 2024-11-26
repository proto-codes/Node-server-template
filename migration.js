require('dotenv').config();
const mysql = require('mysql2');

// Create a MySQL connection using environment variables
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Connect to MySQL
connection.connect((err) => {
  if (err) {
    return console.error('Error connecting to the database: ' + err.stack);
  }
  console.log('Connected to MySQL');
  
  // Function to run migration queries
  const runMigration = (query, description) => {
    connection.query(query, (err, results) => {
      if (err) {
        console.error(`Error creating ${description}:`, err);
      } else {
        console.log(`${description} created or already exists.`);
      }
    });
  };

  // SQL query to create the users table if it doesn't exist
  const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(50) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  // SQL query to create the active_tokens table if it doesn't exist
  const createActiveTokensTableQuery = `
    CREATE TABLE IF NOT EXISTS active_tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL UNIQUE,
      refresh_token TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `;
  
  // SQL query to create the profile table if it doesn't exist
  const createProfileTableQuery = `
    CREATE TABLE IF NOT EXISTS profile (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL UNIQUE,
      bio TEXT,
      profile_pics MEDIUMBLOB,
      phone_number VARCHAR(20),
      birthday DATE,
      address VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `;

  // Run migrations
  runMigration(createUsersTableQuery, 'Users table');
  runMigration(createActiveTokensTableQuery, 'Active tokens table');
  runMigration(createProfileTableQuery, 'Profile table');

  // Close the connection after all migrations
  connection.end((err) => {
    if (err) {
      console.error('Error closing the connection:', err);
      return;
    }
    console.log('Connection closed');
  });
});
