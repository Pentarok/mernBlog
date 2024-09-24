/* const express =require('express');
const mongoose=require('mongoose');
const cors = require('cors');
const userModel = require('./models/usermodel.js')
const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://127.0.0.1:27017/Employees')
.then(
    console.log('connected to database')
)
app.listen(3000,()=>{
    console.log("server is running on port 3000")
})
app.get('/user', async (req,res)=>{
    const users = await userModel.find({});
    res.status(200).json(users)
})
app.get('/users/:id', async (req,res)=>{
    const { id }= req.params;
    const user = await userModel.findById(id);
    res.status(200).json(user)
})
app.get('/users', (req,res)=>{
  try{
    const users= userModel.find({});
    res.status(200).json(users)
  } catch{
    err=>console.log(err)
  }
})
app.get('/users/update/:id',async (req,res)=>{
    const {id}= req.params;
    const user = await userModel.findById(id)
    res.status(200).json(user);
})
app.delete('/user/:id',(req,res)=>{
    const  id =req.params.id;
    userModel.findByIdAndDelete({_id: id});
})
app.put('/users/update/:id',async (req,res)=>{
    const {id}= req.params;
    const user = await userModel.findByIdAndUpdate(id,req.body)
    res.status(200).json(user);
})
app.put('/update/:id',async (req,res)=>{
    const { id }= req.params;
    const updatedProduct = await userModel.findByIdAndUpdate(id,req.body);
    res.status(200).json(console.log(updatedProduct))
})
app.post('/register',(req,res)=>{
    userModel.create(req.body).then(
result=> res.json(result)).catch(
            err=> console.log(err)
        )
    
}) */


const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const CookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const userModel = require('./models/usermodel.js');
const app = express();

app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/Users')
    .then(() => console.log('connected to database'));

app.listen(3000, () => {
    console.log("server is running on port 3000");
});

app.get('/user', async (req, res) => {
    const users = await userModel.find({});
    res.status(200).json(users);
});

app.get('/users/:id', async (req, res) => {
    const { id } = req.params;
    const user = await userModel.findById(id);
    res.status(200).json(user);
});

app.delete('/user/:id', async (req, res) => {
    const { id } = req.params;
    await userModel.findByIdAndDelete(id);  // Await the delete operation
    res.status(200).json({ message: 'User deleted successfully' });
});

app.put('/users/update/:id', async (req, res) => {
    const { id } = req.params;
    const user = await userModel.findByIdAndUpdate(id, req.body, { new: true });
    res.status(200).json(user);
});

app.get('/users/update/:id', async (req, res) => {
    const { id } = req.params;
    const user = await userModel.findById(id);
    res.status(200).json(user);
});


app.post('/register', (req, res) => {
    userModel.create(req.body)
        .then(result => res.json(result))
        .catch(err => console.log(err));
});
app.post('/signup',(req,res)=>{
    const {name, email, password}=req.body;
    bcrypt.hash(password,10)
    .then(hash=>{
        userModel.create({name,email,password:hash})
        .then(res=>res.status(200).json('User created successfully'))
        .catch(err=>res.json(err))
    })
})

