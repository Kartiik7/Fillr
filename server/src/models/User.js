const mongoose = require('mongoose');

const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profile: {
    personal: {
      name: { type: String, default: '' },
      email: { type: String, default: '' },
      phone: { type: String, default: '' },
      gender: { type: String, default: '' }, // Male/Female/Other
      dob: { type: String, default: '' }, // Date of Birth (YYYY-MM-DD)
      age: { type: String, default: '' }, // Age in years
      permanent_address: { type: String, default: '' }, // Permanent address
    },
    academics: {
      tenth_percentage: { type: String, default: '' },
      twelfth_percentage: { type: String, default: '' },
      diploma_percentage: { type: String, default: '' }, // Diploma percentage
      cgpa: { type: String, default: '' },
      graduation_percentage: { type: String, default: '' },
      pg_percentage: { type: String, default: '' },
      active_backlog: { type: String, default: 'No' }, // Yes/No
      backlog_count: { type: String, default: '0' },
      gap_months: { type: String, default: '0' }, // Gap in education (months)
    },
    ids: {
      uid: { type: String, default: '' },
      roll_number: { type: String, default: '' },
      university_roll_number: { type: String, default: '' },
    },
    links: {
      github: { type: String, default: '' },
      linkedin: { type: String, default: '' },
      portfolio: { type: String, default: '' },
    },
    // New fields for Placement Support
    education: {
      college_name: { type: String, default: '' },
      batch: { type: String, default: '' }, // e.g. 2024
      program: { type: String, default: '' }, // e.g. B.Tech
      stream: { type: String, default: '' }, // e.g. CSE
    },
    placement: {
      position_applying: { type: String, default: '' },
    },
  },
}, { timestamps: true });

// Measure password strength or add validation here if needed

// Encrypt password using bcrypt
userSchema.pre('save', async function () {
  if (!this.isModified('password')) {
    return;
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Match user entered password to hashed password in database
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
