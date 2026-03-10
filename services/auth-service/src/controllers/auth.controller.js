import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import axios from "axios";

// Helper: Tạo bộ đôi token
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user._id, role: user.internal_role, permissions: user.permissions },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" },
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" },
  );

  return { accessToken, refreshToken };
};

// 1. ĐĂNG KÝ (Logic: Hash tự động trong Model nên Controller rất sạch)
export const register = async (req, res) => {
  try {
    const { full_name, email, password, phone } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "Email đã được đăng ký" });
    }

    const user = await User.create({ full_name, email, password, phone });

    res.status(201).json({
      success: true,
      message: "Đăng ký thành công. Vui lòng kiểm tra email xác thực.",
      user: { id: user._id, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// 2. ĐĂNG NHẬP (Logic: Sử dụng HttpOnly Cookie)
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Tìm user và lấy trường password đã bị ẩn (select: false)
    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.comparePassword(password))) {
      return res
        .status(401)
        .json({ message: "Thông tin đăng nhập không chính xác" });
    }

    // Tạo cặp token
    const { accessToken, refreshToken } = generateTokens(user);

    // Lưu Refresh Token vào Database (Hỗ trợ đa thiết bị)
    user.refreshTokens.push({
      token: refreshToken,
      userAgent: req.headers["user-agent"],
      ipAddress: req.ip,
    });

    // Giới hạn tối đa 3 thiết bị (Giữ cho mảng tokens không quá lớn)
    if (user.refreshTokens.length > 3) user.refreshTokens.shift();

    user.last_login_at = new Date();
    await user.save();

    // Gửi Refresh Token qua Cookie bảo mật
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // JS không đọc được (Chống XSS)
      secure: process.env.NODE_ENV === "production", // Chỉ gửi qua HTTPS
      sameSite: "strict", // Chống CSRF
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
    });

    // Trả về Access Token qua JSON
    res.status(200).json({
      success: true,
      accessToken,
      user,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const facebookLogin = async (req, res) => {
  try {
    const {facebookId, accessToken: shortLivedToken} = req.body;
    // check token validate
    if(!facebookId || !shortLivedToken) {
    return res.status(400).json({message: "Missing facebook information"})
    }
    // switch to long-lived token 
    let longLivedToken = shortLivedToken;
    try {
      const tokenResponse = await axios.get('https://graph.facebook.com/v23.0/oauth/access_token', {
        params: {
          grant_type: 'fb_exchange_token',
          client_id: process.env.FACEBOOK_APP_ID,
          client_secret: process.env.FACEBOOK_APP_SECRET,
          fb_exchange_token: shortLivedToken,
        },
      });
      longLivedToken = tokenResponse.data.access_token;
    } catch (err) {
    } 
    // get user info from facebook
    const fbProfile = await axios.get('https://graph.facebook.com/me', {
      params: {
        access_token: longLivedToken,
        fields: 'id,name,email,picture.type(large)',
      },
    });

    const {id, name, email, picture } = fbProfile.data;

    // check user exist 
    let user = await User.findOne({$or: [{ facebookId: id }, { email }]});

    if(!user) {
      user = await User.create({
        full_name: name,
        email: email || `${id}@facebook.com`,
        facebookId: id,
        avatar: picture?.data?.url,
        status: "active",
        emailVerified: true,
      });
    } else {
      // update information if user existed
      user.facebookId = id;
      user.facebookAccessToken = longLivedToken;
      user.last_login_at = new Date();
      await user.save();
    }

    // create token of system
    const { accessToken, refreshToken } = generateTokens(user);

    // save RT to DB and sent cookie
    user.refreshTokens.push({ token: refreshToken, ipAddress: req.ip });
    await user.save();

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    })

    res.status(200).json({ success: true, accessToken, user});
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
}

// 3. REFRESH TOKEN (Logic: Xoay vòng token - Refresh Token Rotation)
export const refresh = async (req, res) => {
  const { refreshToken } = req.cookies;
  if (!refreshToken)
    return res.status(401).json({ message: "Không tìm thấy phiên làm việc" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findOne({
      _id: decoded.id,
      "refreshTokens.token": refreshToken,
    });

    if (!user)
      return res
        .status(403)
        .json({ message: "Phiên làm việc không hợp lệ hoặc đã bị thu hồi" });

    // Tạo cặp token mới (Xoay vòng)
    const tokens = generateTokens(user);

    // Thay thế token cũ bằng token mới trong Database  
    user.refreshTokens = user.refreshTokens.filter(
      (t) => t.token !== refreshToken,
    );
    user.refreshTokens.push({ token: tokens.refreshToken, ipAddress: req.ip });
    await user.save();

    // Gửi lại cookie mới
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken: tokens.accessToken });
  } catch (error) {
    return res.status(403).json({ message: "Token đã hết hạn" });
  }
};

export const logout = async (req, res) => {
  const { refreshToken } = req.cookies;
  if (refreshToken) {
    await User.findOneAndUpdate(
      { "refreshTokens.token": refreshToken },
      { $pull: { refreshTokens: { token: refreshToken } } },
    );
  }
  res.clearCookie("refreshToken");
  res.status(200).json({ message: "Đã đăng xuất" });
};



export const resetPassword = async ( req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // hash token user sent to compare with token in DB
    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

      // find user with this token match and token not expired
      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
      });

      // check user exist
      if(!user) {
        return res.status(400).json({
          success: false,
          message: "Token not valid",
        });
      }
      
      // update password new 
      user.password = password;
      
      // clear token and expired time
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;

      // When change password, logout all devices
      user.refreshTokens = [];
      await user.save();
      res.status(200).json({
        success: true,
        message: "Password reset successful. Please login again.",
      });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "System Error",
    });
  }
}


export const changePassword = async (req, res) => {
  const userId = req.user.id;

  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(userId).select("+password");

  const match = await user.comparePassword(oldPassword);

  if (!match) {
    return res.status(400).json({
      message: "Old password incorrect",
    });
  }

  user.password = newPassword;

  // logout all devices
  user.refreshTokens = [];

  await user.save();

  res.json({
    message: "Password changed successfully",
  });
};