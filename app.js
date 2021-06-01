//jshint esversion:6
require('dotenv').config();//configured it to be able to access our enviroment variables
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');//require cookies session at first
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));//adding public folder as a static resource
app.set('view engine', 'ejs');//setting our view engine to be ejs
app.use(bodyParser.urlencoded({//setup body parser
  extended: true
}));

app.use(session({//using express session & setting up with some initial configuration
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());//initialize it for using passport
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});// connecting mongoose to default port of mongodb/nameof the db then flag
mongoose.set("useCreateIndex", true);//for deprecation warning

const userSchema = new mongoose.Schema ({//creating new mongoose schema fot setup our new user database & these schema will be saved in DB
  email: String,
  password: String,
  googleId: String,
  secret: String
});
//plugin is extra bits of packaged code that you can add to the mongoose schemas to extend their functionality
userSchema.plugin(passportLocalMongoose);//we add a plugin with user schema & plugin is passportLocalMongoose that is use to hash & salt our passwords & to save our users into our MongoDB database
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
//create local login strategy
passport.use(User.createStrategy());//create strategy is local strategy to authinticate users using their name & password & also to serializeUser & deserializeUser

passport.serializeUser(function(user, done) {//serializ creates that fortune cookie & stuffs the message namely our users identifications into the cookie
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {//deserialize allows passport to be able to crumble the cookie & discover the msg inside which is who the user is & all of their identification so that we can authinticate them on our server
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({//for using google strategy to login our users paaing all things to help google recoznize our app which we have setup in google cloud
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  //when google authintication has already completed then this cf triggered so we log tyheir profile & create them as user on DB
  function(accessToken, refreshToken, profile, cb) {//callback function where google sends back a access token that allows usto get data related to the user which allows us to acess the user's data for a longer period of time
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){//targetting the root route to render the home homepage
  res.render("home");
});

app.get("/auth/google",//auth/google will initiate authintication on google's server asking them for the user's profile once they have logged in
  passport.authenticate('google', { scope: ["profile"] })//use passport to authinticateour user usingthe google strategy here profile includes email userID on google
);

app.get("/auth/google/secrets",//once auth/google is successfull it will redirect here where we will authinticate user locally & save their login session
  passport.authenticate('google', { failureRedirect: "/login" }),//if authintication failed then redirect user to login page again
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;//saving the secrets that user posted

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){//to identify which user submit which secret so we use req.user.id
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){//save this founduser with their newly updated secret
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");//deauthinticate user & end that user session
});

app.post("/register", function(req, res){//when a new user register & post method gets hit in register.ejs

  User.register({username: req.body.username}, req.body.password, function(err, user){//by following npmjs/packages/packages-local-mongoose-module
    if (err) {
      console.log(err);
      res.redirect("/register");//if there is err we redirect user to register page again for another try
    } else {
      passport.authenticate("local")(req, res, function(){//if no err then we authinticate our user using passport then callback func will be triggered if the authintication is successfullysetup a cookie that savedtheir current logged in session
        res.redirect("/secrets");//when user registered successfully then he will be directed to secrets page
      });
    }
  });

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){//this method comes from passport & we have to pass in the new user that comes from the login credentials that the user provided on our login page & give callback function which can return error if we are unable to find that user with that username in our DB
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){//using local strategy means username & password
        res.redirect("/secrets");
      });
    }
  });

});







app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
