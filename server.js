require('dotenv').config(); // Ensure dotenv is loaded
const bucketName = process.env.BUCKET_NAME;

console.log('S3 Bucket Name:', bucketName); // This
const nodemailer = require('nodemailer');

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const UserModel = require('./models/CreateUser');
const PostModel = require('./models/CreatePost');
const jwt = require('jsonwebtoken');

const multer = require('multer');  // Import multer
const multerS3 = require('multer-s3');  // Import multer S3

const app = express();



// CORS middleware configuration
app.use(cors({
  origin: "https://front-blog-eta.vercel.app", // Allow requests only from this origin
  methods: ["GET", "POST", "PUT", "DELETE"], // Specify allowed methods
  credentials: true // Allow credentials (like cookies, authorization headers, etc.)
}));



app.use(express.json());
app.use(cookieParser());


const dbUri = process.env.MONGO_URI || 'mongodb://localhost:27017/yourDBName';
console.log("Connecting to MongoDB...");
const Uri= 'mongodb://127.0.0.1:27017/Employees'
mongoose.connect(dbUri, {
    socketTimeoutMS: 10000,  // 10 seconds timeout
    connectTimeoutMS: 10000,  // 10 seconds timeout
}).then(() => {
    console.log("Connected to the database");
}).catch((err) => {
    console.error("MongoDB connection error:", err.message);
});



app.listen('3000', () => {
    console.log('server is running on port 3000');
});
const AWS = require('aws-sdk'); // Ensure AWS SDK is imported



const ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const REGION = process.env.AWS_REGION;
const BUCKET_NAME = process.env.BUCKET_NAME; // Ensure BUCKET_NAME is defined

const s3 = new AWS.S3({
    httpOptions: { timeout: 300000 } ,// A
    credentials: {
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: SECRET_ACCESS_KEY,
    },
    region: REGION
});

const uploadToAws = (req, res, next) => {
    const upload = multer({
        storage: multerS3({
            s3: s3,
            bucket: BUCKET_NAME,
            metadata: function(req, file, cb) {
                cb(null, { fieldname: file.fieldname });
            },
            key: function(req, file, cb) {
                cb(null, file.originalname);
            }
        })
    }).single("file");

    // First, upload the file
    upload(req, res, (err) => {
        if (err) {
            console.error("S3 upload error:", err);
            return res.status(500).json({ error: "Error occurred while uploading" });
        }

        // Log the uploaded file information
        console.log("Request file info:", req.file);

        // Token Check
        const token = req.cookies.token;
        if (!token) {
            console.error("Token is missing.");
            return res.status(401).json({ error: "Token is missing" });
        }

        // Verify token
        jwt.verify(token, "manu-secret-key", (err, decoded) => {
            if (err) {
                console.error("Token verification failed:", err.message);
                return res.status(401).json({ error: "Token is invalid or expired" });
            }

            // Add decoded user info to the request for later use
            req.user = decoded;
            console.log("Token successfully decoded:", decoded);
            
            // Proceed to the next middleware or route handler
            next();
        });
    });
};


const verifyAdmin = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
      console.error("Token is missing");
      return res.status(401).json({ message: "Token is missing" });
  } else {
      jwt.verify(token, "manu-secret-key", (err, decoded) => {
          if (err) {
              console.error("Token verification error:", err);
              return res.status(401).json({ message: "Token verification failed" });
          } else {
              if (decoded.role === 'admin') {
                  console.log("Admin access granted");
                  next(); // Proceed to the next middleware/route handler
              } else {
                  console.warn("User is not an admin");
                  return res.status(403).json({ message: "You do not have admin access" });
              }
          }
      });
  }
};

app.get('/dashboard', verifyAdmin, (req, res) => {
 
  res.json('success')
});


const verifyUser=(req,res,next)=>{
  const token = req.cookies.token;
  if(!token){
  return    res.json("Token is missing");
  }else{
      jwt.verify(token,"manu-secret-key",(err,decoded)=>{
          if(err){
              res.json("Token error")
          }else{
              if(decoded.role='visitor'){
                  next();
              }else{
                  return res.json("Invalid")
              }
          }
      })
  }
}

app.get('/verifyuser',verifyUser,(req,res)=>{
  res.json("Success")
})



app.post('/posts', uploadToAws, (req, res) => {
    const { content, title, summary } = req.body;
    const authorname = req.user.author; // Get the author name from the decoded token
    const userId = req.user.id; // Get the user ID from the decoded token
    const fileUrl = req.file ? req.file.location : null;

    // Validate required fields
    if (!title || !summary || !content) {
        console.error("Missing required fields: title, summary, content");
        return res.status(400).json({ error: "All fields are required" });
    }

    // Attempt to create a new post in MongoDB
    console.log("Creating post in MongoDB...");

    PostModel.create({
        title,
        summary,
        content,
        file: fileUrl,
        author: authorname,
        user: userId
    })
    .then((post) => {
        console.log("Post created successfully:", post._id);
        res.status(201).json({ status: 'Ok', post });
    })
    .catch((err) => {
        console.error("MongoDB post creation failed:", err.message);
        res.status(500).json({ error: "Post creation failed", details: err });
    });
});

// Get all posts
app.get('/posts', async (req, res) => {
    const posts = await PostModel.find({});
    res.json({ posts });
});

app.get('/post/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const post = await PostModel.findById(id);
        res.json(post);
    } catch (error) {
        res.json({ error });
    }
});

// Update a post and handle file uploads to S3
app.put('/post/update/:id', uploadToAws, async (req, res) => {
    try {
        const { id } = req.params;
        const post = await PostModel.findById(id);

        let newFileUrl = post.file; // Default to existing file URL
        if (req.file) {
          let oldFile=post.file;
            // Update to new file URL if a new file is uploaded
            deleteFileFromS3(oldFile);
            newFileUrl = req.file.location;

        }

        const updatedDoc = await PostModel.findByIdAndUpdate(id, {
            title: req.body.title,
            content: req.body.content,
            summary: req.body.summary,
            file: newFileUrl
        }, { new: true });

        res.json(updatedDoc);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete post
async function deleteFileFromS3(fileUrl) {
    try {
      // Parse the file URL and extract the file key
      const parsedUrl = new URL(fileUrl);
      const bucketName = process.env.BUCKET_NAME;
  
      if (parsedUrl.host === `${bucketName}.s3.${process.env.AWS_REGION}.amazonaws.com`) {
        // Extract key from virtual-hosted-style URL
        const fileKey = decodeURIComponent(parsedUrl.pathname.slice(1));
        console.log("Extracted file key:", fileKey);
  
        // Delete the file from S3
        const deleteParams = {
          Bucket: bucketName,
          Key: fileKey
        };
        const deleteResult = await s3.deleteObject(deleteParams).promise();
        console.log("S3 delete result:", deleteResult);
      } else {
        console.error("Invalid file URL format:", fileUrl);
      }
    } catch (error) {
      console.error("Error deleting file from S3:", error);
    }
  }
  
  // Example usage:


app.post('/posts/:id', async (req, res) => {
    try {
        // Find the post by ID
        const post = await PostModel.findById(req.params.id);
        
        if (!post) {
            console.error("Post not found:", req.params.id);
            return res.status(404).json({ message: "Post not found" });
        }

        // Extract file URL and check if there is an associated file
        const fileUrl = post.file;
        if (fileUrl) {
          
            deleteFileFromS3(fileUrl)
        } else {
            console.log("No file associated with this post or the file is null.");
        }

        // Delete the post from the database
        await PostModel.findByIdAndDelete(req.params.id);
        console.log(`Post ${req.params.id} deleted successfully`);

        res.json({ status: 'Ok', message: 'Post and associated file deleted successfully' });
    } catch (err) {
        console.error("Error deleting post or file:", err);
        res.status(500).json({ error: "Post deletion failed", details: err.message });
    }
});

// Configure Nodemailer Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // You can use any other email service provider
  auth: {
    user: process.env.EMAIL_USER,  // Email user from .env file
    pass: process.env.EMAIL_PASS   // Email password from .env file
  }
});

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User with this email does not exist" });
    }

    // Generate a reset token (JWT)
    const resetToken = jwt.sign(
      { email: user.email, id: user._id },
      process.env.JWT_RESET_PASSWORD_KEY,
      { expiresIn: '1h' }  // Token expires in 1 hour
    );

    // Define the reset URL to be sent in the email

    const frontEndEnpoint=process.env.WEB_URL
    const resetURL = `${frontEndEnpoint}/reset-password/${user._id}/${resetToken}`;

    // Email content
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <p>You requested a password reset.</p>
        <p>Click the following link to reset your password: <a href="${resetURL}">${resetURL}</a></p>
        <p>This link will expire in 1 hour.</p>
      `
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ error: "Failed to send email" });
      } else {
        console.log('Email sent: ' + info.response);
        return res.json({ message: 'Password reset email sent' });
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Server error" });
  }
});

// Password Reset Route
app.post('/reset-password/:id/:token', async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    // Verify the reset token
    jwt.verify(token, process.env.JWT_RESET_PASSWORD_KEY, async (err, decoded) => {
      if (err) {
        return res.status(400).json({ error: "Invalid or expired reset token" });
      }

      // Find the user by ID
      const user = await UserModel.findById(id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Update the user's password in the database
      user.password = hashedPassword;
      await user.save();

      res.json({ message: "Password has been reset successfully" });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});
app.post('/signup',async (req,res)=>{
  
    try {
        const { name, email, password } = req.body;
      
        // Check if the user already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ error: "Account already exists with this email" });
        }
      
        const hashedPassword = await bcrypt.hash(password, 10);
        const userDoc = await UserModel.create({ name, email, password: hashedPassword });
      
        return res.json('Ok')
      } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Something went wrong. Please try again later." });
      }
      
})
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userExist = await UserModel.findOne({ email: email });

    if (userExist) {
      bcrypt.compare(password, userExist.password, (err, isMatch) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return res.status(500).json({ message: 'Internal server error' });
        }

        if (isMatch)   
 {
          const   token = jwt.sign({
            email: userExist.email,
            id: userExist._id,
            role: userExist.role,
            author: userExist.name,
          },
          'manu-secret-key',
          { expiresIn: '1d' });

          res.cookie('token', token, { 
  httpOnly: true, 
  secure: process.env.NODE_ENV === 'production', 
  sameSite: 'None'
});

          res.json({ userExist, message: 'Login success' });
        } else {
          res.json({ status: '401', message: 'Your credentials are invalid' }); // Use 401 for unauthorized
        }
      });
    } else {
      res.json({ message: 'Account does not exist' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




















app.get('/user',(req,res)=>{
    const oldtoken  = req.cookies.token;


    try {
        jwt.verify(oldtoken, "manu-secret-key", async (err, decoded) => {
            if (err) {
                return res.json("Token is invalid or expired");
            } else {
                console.log(decoded)
                authorname=decoded.author;
                userId = decoded.id;
               res.json(decoded)
               
            }
        });
    } catch (error) {
        res.status(500).json("Server error");
    }
})



app.get('/posts', async (req,res)=>{
const posts = await PostModel.find({})
res.json({posts})
})


app.get('/userposts/:userId', async (req,res)=>{
    const { userId }=req.params;
    const userPost = await PostModel.find({user:userId})

    if(userPost){
        res.json(userPost)
    }
})

app.get('/post/:id', async (req,res)=>{
    const {id}=req.params;
    try {
        const post = await PostModel.findById(id);
        res.json(post)
    } catch (error) {
        res.json({error:error})
    }

})



app.get('/user/status',(req,res)=>{
    const oldtoken  = req.cookies.token;


    try {
        jwt.verify(oldtoken, "manu-secret-key", async (err, decoded) => {
            if (err) {
                return res.json("Token is invalid or expired");
            } else {
                console.log(decoded)
               
               res.json('Ok')
               
            }
        });
    } catch (error) {
        res.status(500).json("Server error");
    }
})

app.post('/logout', (req, res) => {
    // Clear the token cookie by setting it to an empty string and expiring it immediately
    res.cookie('token', '', { httpOnly: true, expires: new Date(0) });
    res.json({ message: 'Logout successful' });
});
app.post('/user/social-links/:postId', async (req, res) => {
    const { postId } = req.params;
    const { socialLinks } = req.body;
  
    try {
      // Find the post by ID
      const post = await PostModel.findById(postId);
  
      if (!post) {
        return res.status(404).json({ error: 'Post not found' });
      }
  
      // Append new social links to existing ones, or create a new array if none exist
      post.socialLinks = post.socialLinks ? [...post.socialLinks, ...socialLinks] : socialLinks;
  
      // Save the updated document
      const updatedPost = await post.save();
  
      res.json(updatedPost);
    } catch (error) {
      console.error('Error posting social links:', error);
      res.status(500).json({ error: 'Error posting social links' });
    }
  });
  




app.put('/api/user/profile', async (req, res) => {
    try {
      const { username, email } = req.body;
     
      
     const oldtoken = req.cookies.token;
     // Find and delete the user
     jwt.verify(oldtoken, "manu-secret-key", async (err, decoded) => {
      if (err) {
          return res.json("Token is invalid or expired");
      } else {
         
          userId = decoded.id;
         res.json(decoded)
         
      }
  });
  
      // Validate request
      if (!username || !email) {
        return res.status(400).json({ error: 'Username and email are required.' });
      }
  
      // Find the user and update details
      const updatedUser = await UserModel.findByIdAndUpdate(
        userId,
        { name: username, email },
        { new: true }
      );
  
      if (!updatedUser) {
        return res.status(404).json({ error: 'User not found.' });
      }
  
      res.json({ message: 'Profile updated successfully!', user: updatedUser });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'An error occurred while updating the profile.' });
    }
  });


  app.delete('/api/user/profile', async (req, res) => {
    try {

     const oldtoken = req.cookies.token;
   // Find and delete the user
   jwt.verify(oldtoken, "manu-secret-key", async (err, decoded) => {
    if (err) {
        return res.json("Token is invalid or expired");
    } else {
       
        userId = decoded.id;
       res.json(decoded)
       
    }
});
      const deletedUser = await UserModel.findByIdAndDelete(userId);
  
      if (!deletedUser) {
        return res.status(404).json({ error: 'User not found.' });
      }
  
      res.json({ message: 'Account deleted successfully!' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'An error occurred while deleting the account.' });
    }
  });
  

app.use('*', (req, res) => {
    res.status(404).send('Hello from MERN Blog');
});




