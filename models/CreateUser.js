const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    role:{
        type:String,
        default:'visitor'
    }
})

const UserModel = mongoose.model('employee',UserSchema);
module.exports=UserModel;