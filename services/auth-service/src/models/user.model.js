// services/auth-service/src/models/user.model.js
import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
  {
    full_name: { 
      type: String, 
      required: [true, "Họ và tên là bắt buộc"], 
      trim: true 
    },
    email: { 
      type: String, 
      unique: true, 
      lowercase: true, 
      trim: true,
      validate: [validator.isEmail, "Email không hợp lệ"] 
    },
    phone: {
      type: String,
      trim: true,
      validate: {
        validator: (v) => !v || /^(\+)?\d{9,11}$/.test(v),
        message: "Số điện thoại không hợp lệ"
      }
    },
    password: { 
      type: String, 
      required: [true, "Mật khẩu là bắt buộc"], 
      minlength: 6, 
      select: false 
    },

    internal_role: {
      type: String,
      enum: ["System Admin", "CS Staff", "Accountant", "User"], 
      default: "User",
    },
    permissions: [String], 
    status: {
      type: String,
      enum: ["pending", "active", "inactive", "banned"],
      default: "pending",
    },
    refreshTokens: [
      {
        token: { type: String },
        userAgent: { type: String }, // Lưu thông tin trình duyệt/thiết bị
        ipAddress: { type: String },
        createdAt: { type: Date, default: Date.now }
      }
    ],

    facebookId: { type: String, sparse: true },
    avatar: { type: String, default: null },

    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },
    passwordResetToken: { type: String, select: false },
    passwordResetExpires: { type: Date, select: false },
    
    last_login_at: { type: Date }
  },
  { 
    timestamps: { createdAt: "created_at", updatedAt: "updated_at" },
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

userSchema.index({ email: 1 });
userSchema.index({ "refreshTokens.token": 1 }); 

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.refreshTokens;
  delete obj.emailVerificationToken;
  delete obj.passwordResetToken;
  return obj;
};

const User = mongoose.model("User", userSchema);
export default User;