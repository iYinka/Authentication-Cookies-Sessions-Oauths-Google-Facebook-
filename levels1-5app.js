    //jshint esversion:6

    require('dotenv').config();
    const express = require("express");
    const bodyParser = require("body-parser");
    const ejs = require("ejs");
    const mongoose = require("mongoose");
    const session = require('express-session');
    const passport = require('passport');
    const passportLocalMongoose = require('passport-local-mongoose');
    //const bcrypt = require("bcrypt");
    //const saltRounds = 10;
    //const md5 = require("md5");
    //const encrypt = require("mongoose-encryption");

    const app = express();

    //console.log(process.env.API);

    app.use(express.static("public"));
    app.set('view engine', 'ejs');
    app.use(bodyParser.urlencoded({extended: true}));

    //CALLING SESSION
    app.use(session({
      secret: 'This is my very own secret',
      resave: false,
      saveUninitialized: false
    }));

    //PASSPORT
    app.use(passport.initialize());
    app.use(passport.session());


    ////CONNECT MONGODB
    mongoose.connect('mongodb://localhost:27017/userDB', {useNewUrlParser: true, useUnifiedTopology: true});
    mongoose.set('useCreateIndex', true);

    //schema
    const userSchema = new mongoose.Schema({    //Schema is from mongoose. mongoose.Schema is introduced due to encryption
      email: String,
      password: String
    });

    //FOR THE HASHING AND CRYPTING
    userSchema.plugin(passportLocalMongoose);

    // //ENCRYPTION package added as a plugin
    // const secret = process.env.SECRET;
    // userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

    //model
    const User = new mongoose.model("User", userSchema);

    passport.use(User.createStrategy());


    passport.serializeUser(User.serializeUser());
    passport.deserializeUser(User.deserializeUser());



    app.get("/", function(req, res){
      res.render("home");
    });

    app.get("/login", function(req, res){
      res.render("login");
    });

    app.get("/register", function(req, res){
      res.render("register");
    });

    app.get("/secrets", function(req, res){
      if (req.isAuthenticated()){
        res.render("secrets");
      } else{
        res.redirect("/login");
      }
    });


    app.get("/logout", function(req, res){
      req.logOut();
     res.redirect("/");
    });


    app.post("/register", function(req, res){
      User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, function() {
            res.redirect("/secrets");
          });
        }
      });
    });

    app.route("/login")
      .get(function (req, res) {
          res.render('login');
    })
      .post(function (req, res) {
        passport.authenticate('local', {successRedirect: '/secrets', failureRedirect: '/login',})(req, res);
    });



    // FOR HASHING AND SALTING
    // app.post("/register", function(req, res){
    //   bcrypt.hash(req.body.password, saltRounds, function(err, hash){
    //     const newUser = new User({
    //       email: req.body.username,
    //       password: hash
    //       //password: md5(req.body.password)
    //     });
    //
    //     newUser.save(function(err){
    //       if(err){
    //         console.log(err);
    //       } else {
    //         res.render("secrets");
    //       }
    //     });
    //   });
    // });
    //
    //
    // app.post("/login", function(req, res){
    //   const username = req.body.username;
    //   const password = req.body.password;
    //   //const password = md5(req.body.password);
    //
    //   User.findOne({email: username}, function(err, foundUser){
    //     if(err){
    //       console.log(err);
    //     }else {
    //       if(foundUser){
    //         bcrypt.compare(password, foundUser.password, function(err, result) {
    //           if(result === true){
    //             res.render("secrets");
    //           }
    //         });
    //         //if(foundUser.password === password){     This is for md5
    //           //res.render("secrets");
    //         }
    //       }
    //     });
    //   });



    app.listen(3000, function(){
      console.log("Server started on port 3000");
    });
