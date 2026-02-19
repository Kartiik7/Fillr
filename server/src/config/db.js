const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    // Do not exit process, just log error so server can still start for other routes
    console.error('MongoDB connection failed. specific routes may not work.');
  }
};

module.exports = connectDB;
