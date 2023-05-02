
const localStrategy=require('passport-local').Strategy;
const { authenticate } = require('passport');
const {pool}=require('./dbConfig');
const bcrypt=require('bcrypt');
const passport = require('passport');


function initialize(passport){
    const authenticateUser=(email,password,done)=>{
        pool.query('SELECT * FROM users WHERE email=$1',[email],(error,result)=>{
            if(error) throw error;
            console.log(result.rows);

            if(result.rows.length>0){
                const user=result.rows[0];

                bcrypt.compare(password,user.password,(error,isMatch)=>{
                    if(error) throw error;
                    if(isMatch){
                        return done(null,user);
                    }else{
                        return done(null,false,{message:"The password is incorrect..."})
                    }
                })
            }else{
                return done(null,false,{message:"email is not registered"})
            }

        })

    }

    passport.use(
        new localStrategy(
            {
            usernameField:"email",
            passwordField: "password"
    
            },
            authenticateUser
    ));
    passport.serializeUser((user,done)=> done(null,user.id));
    
    passport.deserializeUser((id,done)=>{
        pool.query(`SELECT * FROM users WHERE id=$1`,[id],(error,result)=>{
            if(error) throw error;
            return done(null,result.rows[0]);
        })
    })
    

}



module.exports=initialize;