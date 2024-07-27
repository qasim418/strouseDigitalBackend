// // backend/db.js
// const mysql = require('mysql');

// const connection = mysql.createConnection({
//   host: 'localhost',
//   user: 'root', // use your MySQL username
//   password: '', // use your MySQL password
//   database: 'usaapp',
// });

// connection.connect((err) => {
//   if (err) throw err;
//   console.log('Connected to MySQL');
// });

// module.exports = connection;
const mysql = require('mysql');
require('dotenv').config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

connection.connect((err) => {
  if (err) {
    console.error('Database connection error:', err);
    throw err;
  }
  console.log('Connected to MySQL');
});

module.exports = connection;
