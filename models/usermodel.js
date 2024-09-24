const mongoose = require('mongoose');
const userSchema = new mongoose.Schema(
{
   username:'String',
    email:'String',
    country:'String',
}
)
const userModel = mongoose.model('user',userSchema);
module.exports=userModel;

