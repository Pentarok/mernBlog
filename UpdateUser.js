// updateUserRole.js
const mongoose = require('mongoose');
const User = require('./models/CreateUser'); // Adjust the path as necessary

// Replace with your MongoDB connection string
const mongoURI = 'mongodb://127.0.0.1:27017/members';

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

async function updateUserRole(userId, newRole) {
    try {
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { role: newRole },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            console.log('User not found');
            return;
        }

        console.log('User role updated successfully:', updatedUser);
    } catch (error) {
        console.error('Error updating user role:', error);
    } finally {
        mongoose.connection.close(); // Close the connection after the operation
    }
}

// Replace with actual user ID and desired new role
const userId = '66d362eeb23a96d8362fb353';
const newRole = 'admin';

updateUserRole(userId, newRole);


