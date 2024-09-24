const mongoose = require('mongoose');
const PostSchema = new mongoose.Schema({
    title:'String',
    content:'String',
    summary:'String',
    file:'String',
    author:'String',
    user:'String',

},{
    timestamps:true
})
const PostModel = mongoose.model('post',PostSchema)
module.exports=PostModel;