const express = require('express');
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PW, {
  host: process.env.DB_HOST,
  dialect: process.env.DB_DIALECT
});

const User = sequelize.define('User', {
    id: {
      type: DataTypes.INTEGER,
      autoIncrement: true,
      primaryKey: true
    },
    accountId: {
      type: DataTypes.STRING,
      unique: true
    },
    nickname: {
      type: DataTypes.STRING
    },
    password: {
      type: DataTypes.STRING
    },
    email: {
      type: DataTypes.STRING
    },
    token: {
      type: DataTypes.STRING
    }
  }, {
    timestamps: false
});

const app = express();
app.use(express.json());

//user

app.post('/user/signup', async (req, res) => {

  const { accountId, nickname, password, email } = req.body;

  console.log(req.body);

  try {

    const thisUser = await User.findOne({ where: { accountId } });

    if (thisUser) {
      return res.status(409).json({
        message: "유저 아이디가 이미 존재합니다.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({ 
        accountId: accountId,
        nickname: nickname,
        password: hashedPassword,
        email: email
    });

    res.status(201).json("성공적으로 자원을 생성하였습니다.");

  } catch (error) {

    console.error(error);
    res.status(500).json({ message: "서버 오류" });

  }
});

app.post('/user/login', async (req, res) => {
    const { accountId, password } = req.body;
  
    try {
  
      const thisUser = await User.findOne({ where: { accountId } });
  
      if(!thisUser) {
  
        return res.status(404).json({ message: '유저를 찾을 수 없습니다.' });
  
      }
  
      const isPasswordValid = await bcrypt.compare(password, thisUser.password);
  
      if (!isPasswordValid) {
  
        return res.status(409).json({ message: "비밀번호가 일치하지 않습니다." });
  
      }
  
      //jwt 토큰 발급
      const accessToken = jwt.sign(
        { 
          accountId: thisUser.accountId,
        }, 
        process.env.SECRET, 
        {
          expiresIn: "1h",
      });
  
      await thisUser.update({
        token: accessToken,
      });
  
      res.status(201).json({ accessToken });
  
    } catch (error) {
  
      console.error(error);
      res.status(500).json({ message: "서버 오류" });
  
    }
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    
  console.log(`Server is running on port ${PORT}`);

});