const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  // specific fields will be added later
}, { timestamps: true });

module.exports = mongoose.model('Profile', profileSchema);
