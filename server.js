const express = require('express');
const mongoose = require ('mongoose');
const bcrypt = require('bcrypt');
const CookieParser = require('cookie-parser');
const multer = require('multer');  // Import multer
const cors = require('cors');
const UserModel = require('./models/CreateUser');
const PostModel =require('./models/CreatePost')
const fs = require('fs');
const jwt = require('jsonwebtoken');



const cookieParser = require('cookie-parser');
var authorname;
var UserId;
const app = express();
app.use('/uploads', express.static('uploads'));


app.use(cors({
    origin:'http://localhost:5173',
    methods:["GET,POST,PUT,DELETE"],
    credentials:true
}));
// middlewares
app.use(express.json());
app.use(cookieParser());
let uri = 'mongodb+srv://og:OG1234@cluster0.sul4j.mongodb.net/Cluster0?retryWrites=true&w=majority&appName=Cluster0' 
/* let uri = 'mongodb+srv://makpentarok:su8vOU44hJDfCnIDK@cluster0.sul4j.mongodb.net/Cluster0?retryWrites=true&w=majority&appName=Cluster0' */
mongoose.connect(uri)
.then(
    console.log('Connected to the database')
)

app.listen('3000',()=>{
    console.log('server is running on port 3000');
})

const verifyUser=(req,res,next)=>{
    const token = req.cookies.token;
    if(!token){
    return    res.json("Token is missing");
    }else{
        jwt.verify(token,"manu-secret-key",(err,decoded)=>{
            if(err){
                res.json("Token error")
            }else{
                if(decoded.role=='admin'){
                    next();
                }else{
                    return res.json("Not admin")
                }
            }
        })
    }
}
app.get('/dashboard',verifyUser,(req,res)=>{
    res.json("Success");
})
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
app.post('/login',async (req,res)=>{
    const {email,password}=req.body;
const userExist = await UserModel.findOne({email:email});
if(userExist){
   bcrypt.compare(password,userExist.password,(err,isMatch)=>{
    if(isMatch){
        const token = jwt.sign({email:userExist.email,id:userExist._id,role:userExist.role,author:userExist.name},
            "manu-secret-key",{expiresIn:'1d'}
        )
        res.cookie('token',token,{httpOnly:true});
        res.json({userExist,message:'Login success'});
    }else{
        res.json({status:'405',message:'Your credentials are invalid'})
    }
   }
   )
}else{
    res.json('Account does not exist')
}
})

app.post('/forgot-password',async (req,res)=>{
    const {email}=req.body;
const userEmail = email;
var UserExist = await UserModel.findOne({email:email})
console.log(UserExist)
if(UserExist){
  var token2 =  jwt.sign({email:UserExist.email,id:UserExist.id},"manu-reset-pwd",{expiresIn:'1d'})
  res.cookie('token2',token2,{httpOnly:true});
}
    //nodemailer to send the password reset link
    var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'makpentarok@gmail.com',
    pass: 'vffh rvfe pscv oxts'
  }
});

var mailOptions = {
  from: 'makpentarok@gmail.com',
  to: userEmail,

  subject: 'Password Reset',
  text: `http://localhost:5173/reset-password/${UserExist.id}/${token2}`
};

transporter.sendMail(mailOptions, function(error, info){
  if (error) {
    console.log(error);
  } else {
    console.log('Email sent: ' + info.response);
    res.json('success')
  }
});
})
app.post('/reset-password/:id/:token', async (req, res) => {
    const { id, token } = req.params;
    const { password } = req.body;  // Note: password should be in the request body, not in params

    try {
        jwt.verify(token, "manu-reset-pwd", async (err, decoded) => {
            if (err) {
                return res.json("Token is invalid or expired");
            } else {
                const hashedPassword = await bcrypt.hash(password, 10); // Use await to handle the promise
                await UserModel.findByIdAndUpdate(id, { password: hashedPassword }); // Await to ensure the update completes
                res.json("Password reset successful");
            }
        });
    } catch (error) {
        res.status(500).json("Server error");
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

const upload = multer({ dest: './uploads' });  // Initialize multer to handle file uploads
app.post('/posts', upload.single('file'), (req, res) => {
    const token = req.cookies.token;  // Get the token from cookies

    if (!token) {
        return res.status(401).json("Token is missing");
    }

    // Verify the token to extract user info
    jwt.verify(token, "manu-secret-key", (err, decoded) => {
        if (err) {
            return res.status(401).json("Token is invalid or expired");
        }

        // Extract author name and user ID from the decoded token
        const authorname = decoded.author;
        const userId = decoded.id;

        // Extract title, summary, and content from the request body
        const { title, summary, content } = req.body;

        // Process the file if it's present
        let filePath = null;
        if (req.file) {
            const { originalname, path } = req.file;
            const ext = originalname.split('.').pop();
            filePath = `${path}.${ext}`;
            fs.renameSync(path, filePath);  // Rename the file to include its extension
        }
        const defaultFile = 'uploads/placeholder.jpg'; // Default placeholder file path

        // Create a new post with or without the file
        PostModel.create({
            title,
            summary,
            content,
            file: filePath || null ,// Use placeholder if no file is uploaded
            author: authorname,
            user: userId
        })
        .then((post) => res.json({ status: 'Ok', post }))
        .catch((err) => res.status(500).json({ error: "Post creation failed", details: err }));
    });
});

app.get('/posts', async (req,res)=>{
const posts = await PostModel.find({})
res.json({posts})
})

app.get('/user',(req,res)=>{
    const oldtoken  = req.cookies.token;


    try {
        jwt.verify(oldtoken, "manu-secret-key", async (err, decoded) => {
            if (err) {
                return res.json("Token is invalid or expired");
            } else {
                console.log(decoded)
               
               res.json(decoded)
               
            }
        });
    } catch (error) {
        res.status(500).json("Server error");
    }
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



app.put('/post/update/:id', upload.single('file'), async (req, res) => {
    try {
        const { id } = req.params;

        // Fetch the current post from the database
        const post = await PostModel.findById(id);

        // If there's a new file uploaded, handle the file replacement logic
        let newPath = post.file; // Default to existing file path
        if (req.file) {
            // Delete the old file if it exists
            if (post.file) {
                fs.unlink(post.file, (err) => {
                    if (err) {
                        console.error('Error deleting old file:', err);
                    } else {
                        console.log('Old file deleted successfully');
                    }
                });
            }

            // Process the new file
            const { originalname, path } = req.file;
            const ext = originalname.split('.').pop();
            newPath = `${path}.${ext}`;
            fs.renameSync(path, newPath);  // Rename the file to include its extension
        }

        // Update the document with the new fields and new file path (if any)
        const updatedDoc = await PostModel.findByIdAndUpdate(id, {
            title: req.body.title,
            content: req.body.content,
            summary: req.body.summary,
            file: newPath, // Use the new file path if a new file was uploaded, else use the existing one
        }, { new: true });

        res.json(updatedDoc);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ensure your file deletion logic only removes the specific post's file
app.post('/posts/:id', async (req, res) => {
    try {
        const post = await PostModel.findById(req.params.id);

        if (!post) {
            return res.status(404).json("Post not found");
        }

        // Remove the file if it is not the placeholder
        if (post.file && post.file !== 'uploads/placeholder.jpg') {
            fs.unlinkSync(post.file);
        }

        await PostModel.findByIdAndDelete(req.params.id);
        res.json({ status: 'Ok', message: 'Post deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: "Post deletion failed", details: err });
    }
});


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
  
/*
const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // or configure to your specific needs

*/



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
  

