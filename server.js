
const express=require("express");
const ejs=require("ejs");
const {pool}=require("./dbConfig");
const bcrypt=require('bcrypt');
const session=require('express-session');
const flash=require("express-flash");
const passport=require('passport');

const initializePassport=require('./passportConfig');

const app=express();


initializePassport(passport);

const PORT=process.env.PORT || 4000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended:false}));
app.use(session({
    secret:"thesecret",
    resave:false,
    saveUninitialized:false
}));


app.use(passport.initialize());
app.use(passport.session());

app.use(flash());




//const currentUser=[];

app.get("/",(req,res)=>{
    res.render("index");
});

app.get("/users/register",checkAuthenticated,(req,res)=>{
    res.render('register');
})

app.get("/users/login",checkAuthenticated,(req,res)=>{
    res.render('login');
})

app.get("/users/dashboard",notAuthenticated,(req,res)=>{
    //let currentUser='Bob';

    res.render('dashboard',{user: req.user.name});
})


app.get("/users/logout",(req,res)=>{
    req.logOut((err)=>{
        if(err){return err};
        res.redirect("/users/login");

    });
})



app.post("/users/register",async (req,res)=>{
    const {name,email,password,password2}=req.body;
console.log({name,email,password,password2});
    // currentUser.push(name);

    let errors=[];

    if(!name||!email||!password||!password2){
        errors.push({message:'Please enter all fields'});
    }

    if(password.length<6){
        errors.push({message:'Password should be at least 6 six characters'}); 
    }

    if(password != password2){
        errors.push({message:'Passwords do not match'});
    }

    if(errors.length>0){
        res.render("register",{errors:errors});
    }else{
        //Form validation have passed

        const hashPassword=await bcrypt.hash(password,10);
        
        console.log(hashPassword);

        pool.query(
            'SELECT * FROM users WHERE email=$1',[email],(error,result)=>{
                if(error) throw error;
                console.log(result.rows);

                if(result.rows.length>0){
                    errors.push({message:'email already registered'});
                    res.render("register",{errors:errors});
                }else{
                    pool.query(`INSERT INTO users(name,email,password) 
                        VALUES($1,$2,$3)`,[name,email,hashPassword],(errorAdd,resultAdd)=>{
                            if(errorAdd) throw errorAdd;
                            console.log(resultAdd.rows);

                            req.flash("success_msg","You are now registered..! How about login...");

                        res.redirect("/users/login");
                    })
                }


            }
        )
        
    }

    console.log(errors);
    //res.redirect("/users/dashboard");
})


app.post("/users/login",passport.authenticate('local',{
    successRedirect:"/users/dashboard",
    failureRedirect:"/users/login",
    failureFlash:true
}))

function checkAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return res.redirect("/users/dashboard");
    }
    next();
}


function notAuthenticated(req,res,next){
    if(!req.isAuthenticated()){
        return res.redirect("/users/login");
    }
    next();
}


app.listen(PORT,()=>{
    console.log(`Server is listning on port ${PORT}...`);
})
