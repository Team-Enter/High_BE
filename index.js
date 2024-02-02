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

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
    
  console.log(`Server is running on port ${PORT}`);

});