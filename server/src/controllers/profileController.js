const User = require('../models/User');

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (user) {
      res.json({
        success: true,
        profile: user.profile,
        email: user.email // Including email at root level as well if needed, but profile has it too
      });
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (user) {
      // Update fields if they exist in request body
      // We expect the request body to contain a 'profile' object or individual fields
      // Requirement: "Accept profile object"
      const { personal, academics, ids, links, education, placement } = req.body.profile || {};

      if (personal) {
        if (personal.name !== undefined) user.profile.personal.name = personal.name;
        if (personal.email !== undefined) user.profile.personal.email = personal.email;
        if (personal.phone !== undefined) user.profile.personal.phone = personal.phone;
        if (personal.gender !== undefined) user.profile.personal.gender = personal.gender;
        if (personal.dob !== undefined) user.profile.personal.dob = personal.dob;
        if (personal.age !== undefined) user.profile.personal.age = personal.age;
        if (personal.permanent_address !== undefined) user.profile.personal.permanent_address = personal.permanent_address;
      }

      if (academics) {
        if (academics.tenth_percentage !== undefined) user.profile.academics.tenth_percentage = academics.tenth_percentage;
        if (academics.twelfth_percentage !== undefined) user.profile.academics.twelfth_percentage = academics.twelfth_percentage;
        if (academics.cgpa !== undefined) user.profile.academics.cgpa = academics.cgpa;
        if (academics.graduation_percentage !== undefined) user.profile.academics.graduation_percentage = academics.graduation_percentage;
        if (academics.pg_percentage !== undefined) user.profile.academics.pg_percentage = academics.pg_percentage;
        if (academics.active_backlog !== undefined) user.profile.academics.active_backlog = academics.active_backlog;
        if (academics.backlog_count !== undefined) user.profile.academics.backlog_count = academics.backlog_count;
        if (academics.gap_months !== undefined) user.profile.academics.gap_months = academics.gap_months;
      }

      if (ids) {
        if (ids.uid !== undefined) user.profile.ids.uid = ids.uid;
        if (ids.roll_number !== undefined) user.profile.ids.roll_number = ids.roll_number;
        if (ids.university_roll_number !== undefined) user.profile.ids.university_roll_number = ids.university_roll_number;
      }

      if (links) {
        if (links.github !== undefined) user.profile.links.github = links.github;
        if (links.linkedin !== undefined) user.profile.links.linkedin = links.linkedin;
        if (links.portfolio !== undefined) user.profile.links.portfolio = links.portfolio;
      }

      if (education) {
        if (education.college_name !== undefined) user.profile.education.college_name = education.college_name;
        if (education.batch !== undefined) user.profile.education.batch = education.batch;
        if (education.program !== undefined) user.profile.education.program = education.program;
        if (education.stream !== undefined) user.profile.education.stream = education.stream;
      }

      if (placement) {
        if (placement.position_applying !== undefined) user.profile.placement.position_applying = placement.position_applying;
      }

      // Mark only profile as modified to avoid password re-hashing
      user.markModified('profile');
      const updatedUser = await user.save();

      res.json({
        success: true,
        message: 'Profile updated successfully',
        profile: updatedUser.profile
      });
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};
