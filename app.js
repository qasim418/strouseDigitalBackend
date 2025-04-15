const express = require('express');
// const axios = require('axios');
const cors = require('cors');
// const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const db = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000; // Use PORT from environment variables
const secretKey = process.env.JWT_SECRET; // Use secret key from environment variables

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// app.use('/images', express.static(path.join(__dirname, 'images')));

// // Multer setup for file uploads
// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     const dir = './images';
//     if (!fs.existsSync(dir)) {
//       fs.mkdirSync(dir);
//     }
//     cb(null, dir);
//   },
//   filename: (req, file, cb) => {
//     cb(null, `${req.user.id}-${Date.now()}-${file.originalname}`);
//   }
// });

// const upload = multer({ storage });


// make a dummy route
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Middleware to verify token and extract user ID
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Login endpoint
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const user = results[0];
    // const token = jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '1h' });
    const token = jwt.sign({ id: user.id, username: user.username }, secretKey);

    res.json({ token });
  });
});


// Get message and user details by user ID
app.get('/api/messages', authenticateToken, (req, res) => {
  const userId = req.user?.id;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized - User ID missing' });
  }

  const messageQuery = 'SELECT * FROM messages WHERE user_id = ?';

  db.query(messageQuery, [userId], (err, messageResults) => {
    if (err) {
      return res.status(500).json({ message: 'Database error on message retrieval' });
    }

    const message = messageResults.length > 0 ? messageResults[0].message : '';

    const userQuery = 'SELECT company_name, link, logo_link FROM users WHERE id = ?';

    db.query(userQuery, [userId], (err, userResults) => {
      if (err) {
        return res.status(500).json({ message: 'Database error on user retrieval' });
      }

      if (!userResults || userResults.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const user = userResults[0];
      const companyName = user.company_name;
      const link = user.link;
      const image = user.logo_link;

      res.json({ message, companyName, link, image });
    });
  });
});



// Update or insert message by user ID
app.put('/api/messages', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { message, url } = req.body; // Include 'url' in the request body

  // Update the URL in the users table
  // print user id and url
  console.log(userId, url);
  const updateUserUrlQuery = 'UPDATE users SET link = ? WHERE id = ?';
  db.query(updateUserUrlQuery, [url, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Database error updating URL' });
    }

    // Check if a message already exists for this user
    const checkQuery = 'SELECT * FROM messages WHERE user_id = ?';
    db.query(checkQuery, [userId], (err, results) => {
      if (err) {
        return res.status(500).json({ message: 'Database error' });
      }

      if (results.length === 0) {
        // Insert a new message
        const insertQuery = 'INSERT INTO messages (user_id, message) VALUES (?, ?)';
        db.query(insertQuery, [userId, message], (err, results) => {
          if (err) {
            return res.status(500).json({ message: 'Database error' });
          }
          res.json({ message: 'Message inserted successfully!' });
        });
      } else {
        // Update existing message
        const updateQuery = 'UPDATE messages SET message = ? WHERE user_id = ?';
        db.query(updateQuery, [message, userId], (err, results) => {
          if (err) {
            return res.status(500).json({ message: 'Database error' });
          }
          res.json({ message: 'Message and URL updated successfully!' });
        });
      }
    });
  });
});


// Placeholder endpoint for sending messages (this can be implemented as needed)
// app.post('/api/send-message', authenticateToken, (req, res) => {
//   const { customerName, phoneNumber } = req.body;
//   const userId = req.user.id;

//   if (!customerName || !phoneNumber) {
//     return res.status(400).json({ message: 'Customer name and phone number are required.' });
//   }

//   // Fetch the message template
//   const query = 'SELECT * FROM messages WHERE user_id = ?';
//   db.query(query, [userId], async (err, results) => {
//     if (err) {
//       return res.status(500).json({ message: 'Database error' });
//     }
//     if (results.length === 0) {
//       return res.status(404).json({ message: 'No message template found for user.' });
//     }

//     // Generate the dynamic message
//     const template = results[0].message;
//     const dynamicMessage = `Hi ${customerName}, ${template}`;

//     // Webhook URL
//     const url = 'https://services.leadconnectorhq.com/hooks/N3TBlLMvb0ffPxvTwkXm/webhook-trigger/0c72bf78-11d2-4960-a6f7-4402c848e3f3';

//     // Data to send
//     const data = {
//       name: customerName,
//       phone_number: phoneNumber,
//       company_name: 'Acme Corp', // You can replace this with actual company name if available
//       message: dynamicMessage
//     };

//     // Set headers, including Content-Type
//     const headers = {
//       'Content-Type': 'application/json'
//     };

//     try {
//       // Making the POST request
//       const response = await fetch(url, {
//         method: 'POST',
//         headers: headers,
//         body: JSON.stringify(data)
//       });

//       const responseBody = await response.text();

//       // Log the response from the server
//       console.log('Status Code:', response.status);
//       console.log('Response Body:', responseBody);

//       if (!response.ok) {
//         return res.status(response.status).json({ message: 'Failed to send message' });
//       }

//       res.status(200).json({ message: 'Message sent successfully!', sentMessage: dynamicMessage });
//     } catch (error) {
//       console.error('Error:', error);
//       res.status(500).json({ message: 'Failed to send message' });
//     }
//   });
// });



// Get images by user ID
app.get('/api/images', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const query = 'SELECT * FROM user_images WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(results);
  });
});

// Get photo_library_link for the authenticated user
app.get('/api/user/photo-library', authenticateToken, (req, res) => {
  const userId = req.user.id; // Get user ID from authenticated token

  const query = 'SELECT photo_library_link FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    if (!results || results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const photoLibraryLink = results[0].photo_library_link;
    res.json({ photoLibraryLink });
  });
});



// Delete image endpoint
app.delete('/api/images/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const imageId = req.params.id;

  const query = 'SELECT * FROM user_images WHERE id = ? AND user_id = ?';
  db.query(query, [imageId, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'Image not found' });
    }

    const imagePath = path.join(__dirname, results[0].image_url);
    fs.unlink(imagePath, (err) => {
      if (err) return res.status(500).json({ message: 'Error deleting file' });

      const deleteQuery = 'DELETE FROM user_images WHERE id = ?';
      db.query(deleteQuery, [imageId], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        res.json({ message: 'Image deleted successfully' });
      });
    });
  });
});

// Get all reviews for the authenticated user
app.get('/api/reviews', authenticateToken, (req, res) => {
  const userId = req.user.id; // Extract user ID from the token
  const query = 'SELECT * FROM user_reviews WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// User updates a response and create a notification for admin
app.put('/api/reviews/:reviewId/response', authenticateToken, (req, res) => {
  const { reviewId } = req.params;
  const { responseText } = req.body;
  const userId = req.user.id;

  const updateQuery = 'UPDATE user_reviews SET response_text = ?, status = \'edited\' WHERE id = ?';
  db.query(updateQuery, [responseText, reviewId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    const notificationQuery = 'INSERT INTO notifications (user_id, review_id, message) VALUES (?, ?, ?)';
    const message = `User ${userId} edited the response for review ${reviewId}`;
    db.query(notificationQuery, [userId, reviewId, message], (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      res.json({ message: 'Response updated and notification sent successfully' });
    });
  });
});


// GET /api/link — returns the link from users table for the logged-in user
app.get('/api/link', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const query = 'SELECT link FROM users WHERE id = ?';

  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    // Check if the link exists for the user
    if (result.length === 0 || !result[0].link) {
      return res.status(404).json({ message: 'Link not found for user' });
    }

    res.json({ link: result[0].link });
  });
});


// API to get Calendly link for authenticated user
app.get('/api/calendly-link', authenticateToken, (req, res) => {
  // Query to get the Calendly link from the admin_calendly_link table
  const query = 'SELECT calendly_link FROM admin_calendly_link LIMIT 1';  // Assuming there's only one record
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }


    if (results.length === 0 || !results[0].calendly_link) {
      return res.status(404).json({ message: 'Calendly link not found' });
    }

    res.json({ calendlyLink: results[0].calendly_link });
  });
});

// Admin Side
// Middleware to verify admin token
const authenticateAdminToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401); // If there's no token, respond with 401 (Unauthorized)

  jwt.verify(token, secretKey, (err, admin) => {
    if (err) return res.sendStatus(403); // If token verification fails, respond with 403 (Forbidden)
    req.admin = admin;
    next();
  });
};


// Create upload directory if not exists
const uploadDir = './uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir); // Save in ./uploads/
  },
  filename: function (req, file, cb) {
    if (!req.admin || !req.admin.id) {
      return cb(new Error('Admin ID not found in request'));
    }
    const uniqueName = `${req.admin.id}-${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM admins WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    if (results.length === 0) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const admin = results[0];
    const token = jwt.sign({ id: admin.id, username: admin.username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Admin dashboard endpoint
app.get('/api/admin/dashboard', authenticateAdminToken, (req, res) => {
  res.json({ message: 'Welcome to the admin dashboard!' });
});

// Fetch all users endpoint
app.get('/api/admin/users', authenticateAdminToken, (req, res) => {
  const query = 'SELECT id, username, password, company_name, link, photo_library_link, logo_link FROM users';

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// Delete a user
app.delete('/api/admin/users/:id', authenticateAdminToken, (req, res) => {
  const userId = req.params.id;
  const deleteQuery = 'DELETE FROM users WHERE id = ?';

  db.query(deleteQuery, [userId], (err, results) => {
    if (err) {
      console.error('Database error:', err); // Print detailed error to console
      return res.status(500).json({ message: 'Database error', error: err.message }); // Send error details in response
    }

    if (results.affectedRows === 0) {
      console.log('User not found:', userId); // Log the case where no user is found
      return res.status(404).json({ message: 'User not found' });
    }

    console.log('User deleted successfully:', userId); // Log successful deletion
    res.json({ message: 'User deleted successfully' });
  });
});

// // Update a user
// app.put('/api/admin/users/:id', authenticateToken, (req, res) => {
//   const userId = req.params.id;
//   const { username, password, company_name, link } = req.body;

//   const updateQuery = `
//     UPDATE users
//     SET username = ?, password = ?, company_name = ?, link = ?
//     WHERE id = ?
//   `;
//   db.query(updateQuery, [username, password, company_name, link, userId], (err, results) => {
//     if (err) return res.status(500).json({ message: 'Database error' });
//     if (results.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
//     res.json({ message: 'User updated successfully' });
//   });
// });

// app.put('/api/admin/users/:id', authenticateAdminToken, upload.single('logo'), (req, res) => {
//   const userId = req.params.id;
//   const { username, password, company_name, link } = req.body;
//   let updateFields = [];
//   let updateValues = [];

//   // Always update these fields
//   updateFields.push('username = ?', 'password = ?', 'company_name = ?', 'link = ?');
//   updateValues.push(username, password, company_name, link);

//   // Check if image is uploaded
//   if (req.file) {
//     const imagePath = `/uploads/${req.file.filename}`;
//     updateFields.push('logo_link = ?');
//     updateValues.push(imagePath);
//   }

//   updateValues.push(userId); // for WHERE clause

//   const updateQuery = `
//     UPDATE users
//     SET ${updateFields.join(', ')}
//     WHERE id = ?
//   `;

//   db.query(updateQuery, updateValues, (err, results) => {
//     if (err) return res.status(500).json({ message: 'Database error', error: err });
//     if (results.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
//     res.json({ message: 'User updated successfully' });
//   });
// });

app.put('/api/admin/users/:id', authenticateAdminToken, upload.single('logo'), (req, res) => {
  const userId = req.params.id;
  const { username, password, company_name, link, photo_library_link } = req.body;
  const file = req.file;

  let updateFields = ['username = ?', 'password = ?', 'company_name = ?', 'link = ?', 'photo_library_link = ?'];
  let updateValues = [username, password, company_name, link, photo_library_link];

  // Full logo URL
  const photoUrl = file ? `${req.protocol}://${req.get('host')}/uploads/${file.filename}` : null;
  if (photoUrl) {
    updateFields.push('logo_link = ?');
    updateValues.push(photoUrl);
  }

  updateValues.push(userId);

  const updateQuery = `
    UPDATE users
    SET ${updateFields.join(', ')}
    WHERE id = ?
  `;

  db.query(updateQuery, updateValues, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    if (results.affectedRows === 0) return res.status(404).json({ message: 'User not found' });

    // Optional: return updated user
    db.query('SELECT * FROM users WHERE id = ?', [userId], (err2, rows) => {
      if (err2) return res.status(500).json({ message: 'Failed to fetch updated user', error: err2 });
      res.json({ message: 'User updated successfully', user: rows[0] });
    });
  });
});


// Add user endpoint
// app.post('/api/admin/users', authenticateAdminToken, (req, res) => {
//   const { username, password, companyName, url, photoLibraryLink } = req.body; // Destructure the URL from the request body
//   const query = 'INSERT INTO users (username, password, company_name, link, photo_library_link ) VALUES (?, ?, ?, ?, ?)'; // Include URL in the query
//   db.query(query, [username, password, companyName, url, photoLibraryLink], (err, results) => { // Include URL in the parameters
//     if (err) return res.status(500).json({ message: 'Database error' });
//     res.json({ message: 'User added successfully', userId: results.insertId });
//   });
// });

app.post('/api/admin/users', authenticateAdminToken, upload.single('photo'), (req, res) => {
  if (!req.admin) {
    return res.status(401).json({ message: 'Unauthorized admin' });
  }

  const { username, password, companyName, url, photoLibraryLink } = req.body;
  const file = req.file;

  // Construct photo URL (adjust host/port if needed)
  const photoUrl = file ? `${req.protocol}://${req.get('host')}/uploads/${file.filename}` : null;

  const query = `
    INSERT INTO users (username, password, company_name, link, photo_library_link, logo_link)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(query, [username, password, companyName, url, photoLibraryLink, photoUrl], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error', error: err });
    res.json({ message: 'User added successfully', userId: results.insertId });
  });
});

// POST: Add Calendly Link for Admin
app.post('/api/admin/calendly-link', authenticateAdminToken, (req, res) => {
  const adminId = req.admin.id;  // The admin's ID from the decoded token
  const { calendlyLink } = req.body;

  if (!calendlyLink) {
    return res.status(400).json({ message: 'Calendly link is required.' });
  }

  const query = 'INSERT INTO admin_calendly_link (admin_id, calendly_link) VALUES (?, ?)';
  db.query(query, [adminId, calendlyLink], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    res.status(201).json({ message: 'Calendly link added successfully!' });
  });
});



// Admin creates a new review with response
app.post('/api/reviews', authenticateAdminToken, (req, res) => {
  const { userId, reviewText, responseText } = req.body;
  const query = 'INSERT INTO user_reviews (user_id, review_text, response_text) VALUES (?, ?, ?)';
  db.query(query, [userId, reviewText, responseText], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Review and response added successfully', reviewId: results.insertId });
  });
});

// Get all reviews for admin
app.get('/api/admin/reviews', authenticateAdminToken, (req, res) => {
  const query = 'SELECT * FROM user_reviews';
  console.log('Get all reviews for admin');
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    console.log('Results:', results);
    res.json(results);
  });
});


// get all notifications for the admin
app.get('/api/notifications', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM notifications';
  db.query(query, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(results);
  });
});

// Mark a notification as read
app.put('/api/notifications/:id/read', authenticateToken, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id; // Extract the user ID from the JWT

  console.log(`Marking notification ${id} as read for user ${userId}`);

  const query = 'UPDATE notifications SET is_read = 1 WHERE id = ? ';
  db.query(query, [id, userId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    res.json({ message: 'Notification marked as read' });
  });
});


// Get images by user ID
app.get('/api/admin/images', authenticateToken, (req, res) => {
  // get user id by req.user.id
  const userId = req.query.userId;
  const query = 'SELECT * FROM user_images WHERE user_id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    res.json(results);
  });
});


// Upload image endpoint
app.post('/api/upload', authenticateToken, (req, res) => {
  const { imageUrl } = req.body; // Receive the image URL from the request body
  const userId = req.user.id;

  const query = 'INSERT INTO user_images (user_id, image_url) VALUES (?, ?)';
  db.query(query, [userId, imageUrl], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });

    res.json({ message: 'Image link saved successfully!', imageUrl });
  });
});

// Admin password change endpoint
app.post('/api/admin/update-password', authenticateToken, (req, res) => {
  const { password } = req.body;
  const userId = req.user.id; // Extracted from JWT token by authenticateAdminToken middleware

  const query = 'UPDATE admins SET password = ? WHERE id = ?';
  db.query(query, [password, userId], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json({ message: 'Password updated successfully' });
  });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
