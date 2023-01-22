require("dotenv").config()
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-find-or-create')


// const bcrypt = require("bcrypt");
// const saltRounds = 10;
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");


mongoose.set('strictQuery', true);

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true})); 
app.use(express.static("public"));
app.use(session({
    secret: "mynameis",
    resave: false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true});

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL :"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
})

app.get("/auth/google",
passport.authenticate('google', { successRedirect: '/',
scope: ['https://www.googleapis.com/auth/plus.login',
'https://www.googleapis.com/auth/userinfo.email']
}));


app.get("/login",function(req,res){
    res.render("login"); 
})

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/register",function(req,res){
    res.render("register");
})

app.get("/secrets",function(req,res){
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }
    // else res.redirect("/login");
    User.find({"secret":{$ne:null}},function(err,foundUser){
        if(err){
            console.log(err);
        }
        else{
            if(foundUser){
                res.render("secrets",{usersWithSecrets:foundUser});
            }
        }
    })
})

app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else res.redirect("/login");
})

app.post("/submit",function(req,res){
   const submittedSecret = req.body.secret;
   User.findById(req.user.id,function(err,foundUser){
    if(err){
        console.log(err);
    } 
    else{
        if(foundUser){
            foundUser.secret = submittedSecret;
            foundUser.save(function(){
                res.redirect("/secrets"); 
            })
        }
    }
})
})

app.get("/logout",function(req,res){
    req.logout(function(err) {
        if (err){
            console.log(err);
        }
        else res.redirect("/");
      });
});

app.post("/register",function(req,res){
    User.register({username: req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        })

        }
    });
});


app.post("/login",function(req,res){
    const user = new User({
        username : req.body.username,
        password : req.body.password
    })
    req.login(user,function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
            })
        }
    })
})

app.listen(3000,function(){
    console.log("server started on port 3000");
})













/*

app.post("/login",function(req,res){
    const username = req.body.username;
    const password = req.body.password;
    User.findOne({email:username},function(err,foundUser){
        if(err){
            console.log(err)
        }else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result==true){
                        res.render("secrets");
                    }
                });
            }
        }
    })
})

app.post("/register",function(req,res){
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email : req.body.username,
            password : hash
        });
        newUser.save(function(err){
            if(!err){
                res.render("secrets");
            }
            else res.render(err);
        });
    });

});

*/