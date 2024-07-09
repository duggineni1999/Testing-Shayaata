const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId  } = require('mongodb');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require("nodemailer");
const app = express();
const path = require('path');
const fs = require('fs');


const host = '192.168.5.40';
const uri = 'mongodb+srv://codeing722:MjPvde7fbaZt4oSS@sahaayata.lthnczn.mongodb.net/?retryWrites=true&w=majority&appName=sahaayata';
const dbName = 'Sahaayata';
const userCollectionName = 'users';
const profilePicturesCollectionName = 'ProfilePictures';
const workshopCollectionName = 'workshop';
const formdataCollectionName = 'formdata';
const userFormDataCollection = 'UserFormData';
const menuCollectionName = 'menu';
const secretKey = 'SPD041803';

// const allowedOrigins = ['http://localhost:3000'];
// const corsOptions = {
//     origin: (origin, callback) => {
//         if (allowedOrigins.includes(origin)) {
//             callback(null, true);
//         } else {
//             callback(new Error('Not allowed by CORS'));
//         }
//     },
// };

// const corsOptions = {
//   origin: (origin, callback) => {
//       callback(null, true);
//   },
// };

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(express.urlencoded({ extended: true }));



const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function connectDB() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const db = client.db(dbName);

        // List existing collections
        const collections = await db.listCollections().toArray();
        const existingCollectionNames = collections.map(collection => collection.name);
        console.log('Existing collections:', existingCollectionNames);

        // Define the collections you need
        const requiredCollections = [userCollectionName, profilePicturesCollectionName, workshopCollectionName, formdataCollectionName, menuCollectionName, userFormDataCollection];

        // Create collections if they don't exist
        for (const collectionName of requiredCollections) {
            if (!existingCollectionNames.includes(collectionName)) {
                await db.createCollection(collectionName);
                console.log(`Created collection: ${collectionName}`);
            }
        }
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

connectDB();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'saidushyanth0418@gmail.com',
    pass: 'kdct ikmp wtna awat'
  }
});


// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password, email, confirmPassword, role } = req.body;

  // Validation checks
  if (!username || !password || !email || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  try {
    // MongoDB collection initialization
    const db = client.db(dbName);
    const collection = db.collection(userCollectionName);

    // Check if username already exists
    const existingUser = await collection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Create new user object with approval false
    const newUser = {
      username,
      password,
      email,
      role: role || 'user',
    
    };

    // Insert new user into database
    const insertResult = await collection.insertOne(newUser);
    const userId = insertResult.insertedId; // Get the inserted user ID

    // Send approval email
    const mailOptions = {
      from: 'saidushyanth0418@gmail.com', // Replace with your Gmail email address
      to: 'saipriyanka0418@gmail.com', // Replace with host email
      subject: 'User Registration Approval',
      text: `Hi ${username},\n\nYour registration request has been received. Click this link to approve: http://192.168.5.56:3000/approval?id=${userId}\n\nRegards,\nYour App Team`,
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
      } else {
        console.log('Email sent:', info.response);
      }
    });

    res.json({
      success: true,
      message: 'User registered successfully. Check your email for approval link.',
      id: userId,
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  } 
});


app.put('/approve-user/:id', async (req, res) => {
  const userId = req.params.id;

  const db = client.db(dbName);
  const collection = db.collection(userCollectionName);

  try {
    const user = await collection.findOne({ _id: new ObjectId(userId) }); // Use findOne with ObjectId
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user approval and role
    user.isApproved = true;
    if (user.role === 'admin') {
      user.isAdmin = true; // Assuming you have an isAdmin field for admins
    }

    await collection.updateOne({ _id: new ObjectId(userId) }, { $set: { isApproved: true, isAdmin: user.isAdmin || false } });

    // Send approval email
    const mailOptions = {
      from: 'saidushyanth0418@gmail.com',
      to: user.email,
      subject: 'Account Approved at OurSite',
      text: `Dear ${user.username},\n\nYour account at OurSite has been approved. You can now login and access your account.\n\nRegards,\nThe  Team`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending approval email:', error);
        res.status(500).json({ error: 'Approval email could not be sent' });
      } else {
        console.log('Approval email sent:', info.response);
        res.json({ message: 'User approved successfully and email sent' });
      }
    });
  } catch (error) {
    console.error('Error approving user:', error);
    res.status(500).json({ error: 'User approval failed' });
  }
});


app.get('/user-details/:id', async (req, res) => {
  const userId = req.params.id;

  const db = client.db(dbName);
  const collection = db.collection(userCollectionName);

  try {
    const user = await collection.findOne({ _id: new ObjectId(userId) }); // Use findOne with ObjectId
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// app.get("/approve-registration/:userId", async (req, res) => {
//   const userId = req.params.userId;

//   if (!ObjectId.isValid(userId)) {
//     return res.status(400).json({ error: "Invalid user ID format" });
//   }

//   const db = client.db(dbName);
//   const collection = db.collection(userCollectionName);

//   try {
//     // Update user approval status to true
//     const result = await collection.updateOne(
//       { _id: new ObjectId(userId) },
//       { $set: { approval: true } }
//     );

//     if (result.modifiedCount === 0) {
//       return res.status(404).json({ error: "User not found or no changes made" });
//     }

//     // Optionally, redirect user to a success page
//     res.redirect("/approved-successfully");
//   } catch (error) {
//     console.error("Error approving registration:", error);
//     res.status(500).json({ error: "Failed to approve registration" });
//   }
// });



// app.post("/login", async (req, res) => {
//   const { username, password } = req.body;
//   if (!username || !password) {
//     return res.status(400).json({ error: "Username and password are required" });
//   }

//   const db = client.db(dbName);
//   const collection = db.collection(userCollectionName);

//   try {
//     const user = await collection.findOne({ username, password });

//     if (!user) {
//       return res.status(401).json({ success: false, message: "Invalid username or password" });
//     }

//     if (!user.approval) {
//       return res.status(401).json({ success: false, message: "User registration pending approval" });
//     }

//     const admin = user.isAdmin;

//     const tokenPayload = {
//       username: user.username,
//       email: user.email,
//       isAdmin: user.isAdmin,
//     };

//     const token = jwt.sign(tokenPayload, secretKey, { expiresIn: "10m" });

//     res.json({
//       success: true,
//       message: "Login successful",
//       id: user._id,
//       token,
//       isAdmin: admin,
//     });
//   } catch (error) {
//     console.error("Error authenticating user:", error);
//     res.status(500).json({ error: error.message }); // Send the actual error message for debugging
//   }
// });


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    
    const db = client.db(dbName);
    const collection = db.collection(userCollectionName);

    // Find user by username
    const user = await collection.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    // Check if user is approved
    if (!user.isApproved) {
      return res.status(401).json({ success: false, message: 'User registration pending approval' });
    }

    // Check password (Assuming passwords are stored as plain text for simplicity; use hashing in production)
    if (user.password !== password) {
      return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    const admin = user.isAdmin;

    const tokenPayload = {
      username: user.username,
      email: user.email,
      isAdmin: user.isAdmin,
    };

    const token = jwt.sign(tokenPayload, secretKey, { expiresIn: '10m' });

    res.json({
      success: true,
      message: 'Login successful',
      id: user._id,
      token,
      isAdmin: admin,
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  } 
});



function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}


   
app.post('/uploadProfilePicture', async (req, res) => {
    const { userId } = req.body;
    const profilePicture = req.file;

    if (!userId || !profilePicture) {
        return res.status(400).json({ error: 'User ID and profile picture are required' });
    }

    const db = client.db(dbName);
    const collection = db.collection(profilePicturesCollectionName);

    try {
        const existingUser = await collection.findOne({ userId });
        if (existingUser) {
            await collection.updateOne({ userId }, { $set: { profilePicture: profilePicture.path } });
        } else {
            await collection.insertOne({ userId, profilePicture: profilePicture.path });
        }
        res.status(201).json({ success: true, imagePath: profilePicture.path });
    } catch (error) {
        console.error('Failed to upload profile picture:', error);
        res.status(500).json({ error: 'Failed to upload profile picture' });
    }
});

app.delete("/removeProfilePicture/:userId", async (req, res) => {
  const { userId } = req.params;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  const db = client.db(dbName);
  const collection = db.collection(profilePicturesCollectionName);

  try {
    await collection.deleteOne({ userId });
    res.status(200).json({ message: "Profile picture removed successfully" });
  } catch (error) {
    console.error("Failed to remove profile picture:", error);
    res.status(500).json({ error: "Failed to remove profile picture" });
  }
});



// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token not provided' });
  }

  jwt.verify(token.split(' ')[1], secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.decoded = decoded;
    next();
  });
}

// Example of protected route using the middleware
app.get('/protected', verifyToken, (req, res) => {
  res.json({ success: true, message: 'Protected route accessed successfully' });
});


function verifyAdmin(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Token not provided" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(408).json({ success: false, message: err.message });
    }
    if (!decoded.isAdmin) {
      return res
        .status(403)
        .json({ success: false, message: "Admin privileges required" });
    }
    req.decoded = decoded;
    next();
  });
}

app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  const db = client.db(dbName);
  const collection = db.collection(userCollectionName);

  try {
    const users = await collection.find().toArray();
    res.json({ success: true, users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// app.post("/workshop", async (req, res) => {
//   const { heading, content, category } = req.body;

//   if (!heading || !content || ! category) {
//     return res.status(400).json({ error: "Heading and content are required" });
//   }

//   const db = client.db(dbName);
//   const collection = db.collection(workshopCollectionName);

//   try {
//     await collection.insertOne({ heading, content ,  category});
//     res
//       .status(201)
//       .json({ message: "Workshop created successfully", heading, content,  category });
//   } catch (error) {
//     console.error("Failed to create workshop:", error);
//     res.status(500).json({ error: "Failed to create workshop" });
//   }
// });


// Add or update workshop
// Add or update workshop
app.post('/workshop', async (req, res) => {
  const { heading, content, category } = req.body;

  if (!heading) {
    return res.status(400).json({ error: 'Heading is required' });
  }

  try {
    // Access the database and collection
    const db = client.db(dbName);
    const collection = db.collection(workshopCollectionName);

    // Check if a workshop with the same heading already exists
    const existingWorkshop = await collection.findOne({ heading });

    if (existingWorkshop) {
      // Workshop with heading already exists, update content if provided
      if (content) {
        const updateResult = await collection.updateOne(
          { heading },
          { $set: { content } }
        );

        console.log('Update Result:', updateResult);

        if (updateResult.modifiedCount === 1) {
          res.status(200).json({ message: 'Workshop updated' });
        } else {
          throw new Error('Failed to update workshop');
        }
      } else {
        res.status(200).json({ message: 'Workshop already exists' });
      }
    } else {
      // Insert new document with heading, content, and category if provided
      const newWorkshop = {
        heading,
        content: content || null,
        category: category || null
      };
      const insertResult = await collection.insertOne(newWorkshop);

      console.log('Insert Result:', insertResult);

      if (insertResult.insertedCount === 1) {
        res.status(200).json({ message: 'Workshop created' });
      } else {
        throw new Error('Failed to create workshop');
      }
    }
  } catch (error) {
    console.error('Failed to process workshop:', error);
    res.status(500).json({ error: 'Failed to process workshop' });
  }
});

// Get workshop by heading
app.get('/workshop/get', async (req, res) => {
  const { heading } = req.query; // Use req.query for GET request

  if (!heading) {
    return res.status(400).json({ error: 'Heading is required' });
  }

  const db = client.db(dbName);
  const collection = db.collection(workshopCollectionName);

  try {
    const workshops = await collection.find({ heading }).toArray();
    res.status(200).json({ workshops });
  } catch (error) {
    console.error('Failed to fetch workshops:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});


app.get("/workshop", async (req, res) => {

  const db = client.db(dbName);
  const collection = db.collection(workshopCollectionName);

  try {
    const workshops = await collection.find().toArray();
    res.status(200).json({ workshops });
 

  } catch (error) {
    console.error("Failed to fetch workshops:", error);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});

app.post("/workshops", async (req, res) => {
  const { heading } = req.body;


  if (!heading) {
    return res.status(400).json({ error: "Heading is required" });
  }

  const db = client.db(dbName);
  const collection = db.collection(workshopCollectionName);

  try {
    const workshop = await collection.findOne({heading:heading});


    if (!workshop) {
      return res.status(404).json({ message: "Workshop not found" });
    }

    res.status(200).json({ workshop });
  } catch (error) {
    console.error("Failed to fetch workshop:", error);
    res.status(500).json({ error: "Failed to fetch data" });
  }
});

app.delete("/workshop/:id", async (req, res) => {
  const workshopId = req.params.id;

  const db = client.db(dbName);
  const collection = db.collection(workshopCollectionName);

  try {
    const result = await collection.deleteOne({
      _id: new MongoClient.ObjectId(workshopId),
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "Workshop not found" });
    }

    res.status(200).json({ message: "Workshop deleted successfully" });
  } catch (error) {
    console.error("Failed to delete workshop:", error);
    res.status(500).json({ error: "Failed to delete workshop" });
  }
});

app.put("/workshop/:id", async (req, res) => {
  const workshopId = req.params.id;
  const { heading, content } = req.body;

  if (!heading || !content) {
    return res.status(400).json({ error: "Heading and content are required" });
  }

  const db = client.db(dbName);
  const collection = db.collection(workshopCollectionName);

  try {
    const result = await collection.updateOne(
      { _id: new MongoClient.ObjectId(workshopId) },
      { $set: { heading, content } }
    );

    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ error: "Workshop not found or no changes made" });
    }

    res.status(200).json({ message: "Workshop updated successfully" });
  } catch (error) {
    console.error("Failed to update workshop:", error);
    res.status(500).json({ error: "Failed to update workshop" });
  }
});


// Get workshop by heading
// app.post('/workshops/get', async (req, res) => {
//   const { heading } = req.body;

//   if (!heading) {
//     return res.status(400).json({ error: 'Heading is required' });
//   }

//   try {
//     // Access the database and collection
//     const db = client.db(dbName);
//     const collection = db.collection(workshopCollectionName);

//     // Find the workshop with the specified heading
//     const results = await collection.find({ heading }).toArray();

//     if (results.length === 0) {
//       return res.status(404).json({ error: 'No workshops found with the specified heading' });
//     }

//     res.json(results);
//   } catch (err) {
//     console.error('Failed to fetch workshop:', err);
//     res.status(500).json({ error: 'Failed to fetch workshop' });
//   }
// });

app.post('/form-post', async (req, res) => {
  const { heading, content } = req.body;

  if (!heading) {
    return res.status(400).json({ error: 'Heading is required' });
  }
  const db = client.db(dbName);
  const formDataCollection = db.collection('formdata');

  try {
    const result = await formDataCollection.updateOne(
      { heading },
      { $set: { content } },
      { upsert: true }
    );

    res.status(200).json({ message: 'Form saved' });
  } catch (error) {
    console.error('Failed to create/update form:', error);
    res.status(500).json({ error: 'Failed to create/update form' });
  }
});

app.get('/form-data', async (req, res) => {
  const db = client.db(dbName);
  const formDataCollection = db.collection('formdata');
  const { heading } = req.query; // Extract 'heading' from query parameters

  try {
      let formData;
      if (heading) {
          formData = await formDataCollection.find({ heading }).toArray();
      } else {
          formData = await formDataCollection.find().toArray();
      }
      res.json(formData);
  } catch (error) {
      console.error('Failed to retrieve form data:', error);
      res.status(500).json({ error: 'Failed to retrieve form data' });
  }
});

// MongoDB Insert API
app.post('/api/insert', async (req, res) => {
  try {
    const newData = req.body; // Assuming JSON data is sent in the request body

    // Access the database and collection
    const db = client.db(dbName);
    const collection = db.collection(userFormDataCollection);

    // Insert new document into MongoDB
    const insertResult = await collection.insertOne(newData);
    console.log('Inserted new document into MongoDB:');

    // Send success response
    res.status(201).json({ message: 'Data inserted into MongoDB', data: insertResult });
  } catch (err) {
    console.error('Error inserting document into MongoDB:', err); // Log MongoDB specific error
    res.status(500).json({ error: 'Failed to insert data into MongoDB' });
  }
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'assets/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + path.extname(file.originalname);
    const newFileName = `profilePicture-${uniqueSuffix}`;
    cb(null, newFileName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000000 }, // Limit file size to 1 MB (adjust as needed)
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.jpg', '.jpeg', '.png'];
    const extname = path.extname(file.originalname).toLowerCase();
    if (!allowedExtensions.includes(extname)) {
      cb(new Error('Unsupported file type'));
    } else {
      cb(null, true);
    }
  }
});

app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;

  const db = client.db(dbName);
  const collection = db.collection(userCollectionName);

  if (!ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  try {
    const user = await collection.findOne({ _id: new ObjectId(userId) });

    if (!user) {
      console.log('User not found');
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error retrieving user:', error);
    res.status(500).json({ error: 'Failed to retrieve user' });
  }
});

app.put('/user/:id', upload.single('profilePicture'), async (req, res) => {
  const userId = req.params.id;
  const { field, value } = req.body; // Assuming req.body contains { field: 'fieldName', value: 'updatedValue' }
  // console.log(field, value)
  try {
    const db = client.db(dbName);
  const collection = db.collection(userCollectionName);

    // Validate if userId is a valid ObjectId
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid user ID format' });
    }

    let profilePictureUrl = null;

    // Handle profile picture upload if a file is selected
    if (req.file) {
      // Move the file to the assets directory (if needed)
      const newFilePath = path.join(__dirname, 'assets', req.file.filename);
      fs.renameSync(req.file.path, newFilePath);

      // Update the profile picture URL
      profilePictureUrl = `http://192.168.5.56:8089/assets/${req.file.filename}`;
    }

    // Prepare update operation based on whether profilePictureUrl needs to be updated
    let updateFields = { [field]: value };
    if (profilePictureUrl) {
      updateFields.profilePicture = profilePictureUrl;
    }

    // Update user document in MongoDB
    const result = await collection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateFields }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }

    // Respond with success message or updated data
    res.status(200).json({ message: `${field} updated successfully` });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: 'Failed to update user profile' });
  }
});


const port = 8000;
app.listen( port, () => {
  console.log(`Server is running on ${port} `);
});
