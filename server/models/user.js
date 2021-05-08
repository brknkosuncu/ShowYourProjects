import mongoose from "mongoose";
import crypto from "crypto";
import bcrypt from "bcryptjs";
const Schema = mongoose.Schema;

const userSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
  id: { type: String },
  dateOfBirth: {
    type: Date,
    required: true,
  },

  about: {
    type: String,
  },
  place: {
    type: String,
    required: true,
  },
  website: {
    type: String,
  },
  profileImage: {
    type: String,
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordExpire: {
    type: Date,
  },
});

userSchema.methods.getResetPasswordTokenFromUser = function () {
  const randomHexString = crypto.randomBytes(15).toString("hex");
  const { RESET_PASSWORD_EXPIRE } = process.env;

  const resetPasswordToken = crypto
    .createHash("SHA256")
    .update(randomHexString)
    .digest("hex");

  this.resetPasswordToken = resetPasswordToken;
  this.resetPasswordExpire = Date.now() + parseInt(RESET_PASSWORD_EXPIRE);

  return resetPasswordToken;
};
userSchema.pre("save", function (next) {
  // Parola Değişmemişse
  if (!this.isModified("password")) {
    next();
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) next(err);

    bcrypt.hash(this.password, salt, (err, hash) => {
      if (err) next(err);
      this.password = hash;
      next();
    });
  });
});

export default mongoose.model("User", userSchema);
