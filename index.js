const express = require('express');
const bcrypt = require("bcrypt");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PW, {
  host: process.env.DB_HOST,
  dialect: process.env.DB_DIALECT,
  port: process.env.DB_PORT
});

const User = sequelize.define('User', {
  id: { //고유번호
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  accountId: { //아이디
    type: DataTypes.STRING,
    unique: true
  },
  nickname: { //닉네임
    type: DataTypes.STRING
  },
  password: { //비밀번호
    type: DataTypes.STRING
  },
  email: { //이메일
    type: DataTypes.STRING
  },
  token: { //토큰
    type: DataTypes.STRING
  }
}, {
  timestamps: false
});

const Feed = sequelize.define('Feed', {
  id: { //고유번호
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  result: { //관련 분야
    type: DataTypes.STRING
  },
  name: { //학교 이름
    type: DataTypes.STRING,
    unique: true
  },
  Stype: { //학교 유형
    type: DataTypes.STRING
  },
  location: { //학교 위치
    type: DataTypes.STRING
  },
  phone: { //학교 번호
    type: DataTypes.STRING
  },
  date: { //설립 일자
    type: DataTypes.STRING
  },
  Etype: { //설립 유형
    type: DataTypes.STRING
  },
  gender: { //성별 구분
    type: DataTypes.STRING
  },
  link: { //홈페이지 링크
    type: DataTypes.STRING
  },
  lesson: { //학교 학과
    type: DataTypes.STRING
  },
}, {
  timestamps: false
});

const app = express();
app.use(express.json());


//user

//회원가입
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

//로그인
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

//로그아웃
app.post('/user/logout', async (req, res) => {
  const authHeader = req.headers.authorization;

  try {

    if(!authHeader) {
      return res.status(401).json({ message: "인증 토큰이 없습니다." });
    }

    const token = authHeader.split(' ')[1];

    const decodedToken = jwt.verify(token, process.env.SECRET);

    const accountId = decodedToken.accountId;

    const thisUser = await User.findOne({ where: { accountId } });

    if (!thisUser) {
      return res.status(404).json({
        message: "요청한 페이지를 찾을 수 없습니다.",
      });
    }

    await thisUser.update({
      token: null,
    });

    return res.status(204).json({
      message: "서버에서 정상적인 변경 또는 삭제 처리가 이루어졌지만, 새롭게 보일 정보가 없습니다.",
    });
    
  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "서버 에러",
    });

  }

});

//사용자 정보 확인
app.get('/user/info', async (req, res) => {
  const authHeader = req.headers.authorization;

  try {

    if (!authHeader) {
      return res.status(401).json({ message: '토큰이 유효하지 않습니다.' });
    }

    const token = authHeader.split(' ')[1];

    const decodedToken = jwt.verify(token, process.env.SECRET);

    const accountId = decodedToken.accountId;

    const thisUser = await User.findOne({ 
      where: { accountId },
      attributes: { exclude: ["id", "password", "token"] },
    });

    if (!thisUser) {
      return res.status(404).json({ message: "'유저를 찾을 수 없습니다.'" });
    }

    res.status(200).json({ 
      accountId: thisUser.accountId,
      nickname: thisUser.nickname,
      email: thisUser.email
    });

  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "서버 에러",
    });

  }

});


//feeds

//고등학교 정보 추가
app.post('/feeds/insert', async (req, res) => {
  const { result, name, Stype, location, phone, date, Etype, gender, link, lesson } = req.body;

  try {

    const feed = await Feed.create({ 
      result: result,
      name: name,
      Stype: Stype,
      location: location,
      phone: phone,
      date: date,
      Etype: Etype,
      gender: gender,
      link: link,
      lesson: lesson
    });

    return res.status(200).json({
      message: "입력 성공",
    });

  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "서버 에러",
    });

  }

})


//고등학교 추천
app.get('/feeds', async (req, res) => {
  const { firstresult, secondresult } = req.query;
  
  const authHeader = req.headers.authorization;

  try {

    if (!authHeader) {
      return res.status(401).json({ message: '토큰이 유효하지 않습니다.' });
    }

    const token = authHeader.split(' ')[1];

    const decodedToken = jwt.verify(token, process.env.SECRET);

    const accountId = decodedToken.accountId;

    const thisUser = await User.findOne({ where: { accountId } });

    if (!thisUser) {
      return res.status(404).json({ message: "유저를 찾을 수 없습니다." });
    }

    let result = firstresult;
    const firstData = await Feed.findAll({ 
      where: { result },
      attributes: { exclude: [ "result", "id", "phone", "date", "Etype", "gender", "link", "lesson"] },
    });

    result = secondresult;
    const secondData = await Feed.findAll({ 
      where: { result },
      attributes: { exclude: [ "result", "id", "phone", "date", "Etype", "gender", "link", "lesson"] },
    });

    res.status(200).json({
      firstData,
      secondData
    });

  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "서버 에러",
    });

  }

});

//고등학교 정보 조회
app.get('/feeds/info', async (req, res) => {
  const { name } = req.query;
  
  const authHeader = req.headers.authorization;

  try {

    if (!authHeader) {
      return res.status(401).json({ message: '토큰이 유효하지 않습니다.' });
    }

    const token = authHeader.split(' ')[1];

    const decodedToken = jwt.verify(token, process.env.SECRET);

    const accountId = decodedToken.accountId;

    const thisUser = await User.findOne({ where: { accountId } });

    if (!thisUser) {
      return res.status(404).json({ message: "유저를 찾을 수 없습니다." });
    }

    const data = await Feed.findOne({ 
      where: { name },
      attributes: { exclude: [ "id", "result" ] },
    });

    const lesson = data.lesson.split(',');

    res.status(200).json({
      "name": data.name,
      "Stype": data.Stype,
      "location": data.location,
      "phone": data.phone,
      "date": data.date,
      "Etype": data.Etype,
      "gender": data.gender,
      "link": data.link,
      "lesson": lesson
    });

  } catch (err) {
    console.log(err);

    return res.status(500).json({
      message: "서버 에러",
    });

  }

});


const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    
  console.log(`Server is running on port ${PORT}`);

});
