import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport"
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv"

const app = express();
const port = 3000;
const saltRounds=10;
env.config();

const db=new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database:process.env.DB_DATABASE,
  password:process.env.DB_PASSWORD,
  port:process.env.DB_PORT,
})
db.connect();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
  secret:process.env.SESSION_SECRET,
  resave: false, //for saving session in postgres database
  saveUninitialized: true,
  cookie:{
    maxAge:1000*60*60
  }
}))

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",async (req,res)=>{
  console.log(req.user)
  if(req.isAuthenticated()) {
    try {
     const result=await db.query("select secret from users where email=$1",[req.user.email]) 
     console.log(result);
     let secret=result.rows[0].secret;
     if(secret)
     res.render("secrets.ejs",{secret: secret});
     else {
      res.render("secrets.ejs",{secret: "This world lives on love, trust and respect!! Please submit your own secret !!"});
     } 
    }
    catch(err) {
      console.log(err);
    }
  }
  else 
  res.redirect("/login");
})

app.get("/auth/google",passport.authenticate("google",
{
  scope:["profile","email"]
}
))

app.get("/auth/google/secrets",passport.authenticate("google",{
successRedirect:"/secrets",
failureRedirect:"/login",
}))

app.get("/logout",(req,res)=>{
  req.logout((err)=>{
    if(err) console.log(err)
    res.redirect("/");
  })
})

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()) {
  res.render("submit.ejs");
  }
  else {
    res.redirect("/login");
  }
})

app.post("/register", async (req, res) => {
  let email=req.body['username'];
  let password=req.body['password'];
  try {
  const checkmail=await db.query("select * from users where email=($1)",[email]);
  if(checkmail.rows.length>0) {
    res.send("User already registered !! Please try logging in");
  }
  else {
  bcrypt.hash(password,saltRounds,async (err,hash)=>{
     if(err)
     console.log(err);
    else {
      const info=await db.query("insert into users(email,password) values($1,$2) returning *",[email,hash]);
      const user=info.rows[0];
      req.logIn(user,(err)=>{
        console.log(err);
        res.redirect("/secrets");
      })
    }
  }) 
  }
} catch(err) {
  console.log(err);
}
});

app.post("/login", passport.authenticate("local",{
      successRedirect:"/secrets",
      failureRedirect:"/login",
})
)

app.post("/submit",async (req,res)=>{
let secret=req.body['secret'];
try {
  await db.query("update users set secret=$1 where email=$2",[secret,req.user.email])
  res.redirect("/secrets");
}
catch(err) {
console.log(err);
}
})

passport.use("local",new Strategy(async function verify(username,password,cb) {
  try {
    const check=await db.query("select * from users where email=($1)",[username]);
    if(check.rows.length>0) {
      const user=check.rows[0];
      const storedpassword=check.rows[0].password;
      bcrypt.compare(password,storedpassword,(err,result)=>{
      if(err)
        return cb(err)
      else {
        if(result)
        return cb(null,user);
        else
        return cb(null, false);
      }
      })
      
    }
    else
    return cb("User not found")
    }
    catch(err) {
      console.log(err);
    }
}))  //cb-callback

passport.use("google",
new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENTID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",

}, async(accessToken, refreshToken, profile, cb)=> {
console.log(profile);
try {
  let result=await db.query("select * from users where email=$1",[profile.email])
  if(result.rows.length===0) {
    const newUser= await db.query("insert into users(email,password) values ($1,$2)",[profile.email,"google"])
    cb(null,newUser.rows[0]);
  } 
  else {
    cb(null,result.rows[0]);
  }
}
catch(err) {
  cb(err);
}
}
))

passport.serializeUser((user,cb)=>{
  cb(null,user);
})
passport.deserializeUser((user,cb)=>{
  cb(null,user);
})
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
