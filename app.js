const express = require('express')
const app = express();
const {User} = require('./model/User');

const mongoose = require('mongoose');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');


//Conecting to database
mongoose.connect('mongodb://127.0.0.1:27017/shopeefy')
.then(()=>{
    console.log('Connected to database');
}).catch((err)=>{
    console.log('Data base is not connected',err)
})



//middleware
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

//task 1 -> create a register route
app.post('/register',async(req,res)=>{
    try{

        const {name,email,password} = req.body;
        //cheacking is any filde missing
        if(!name || !email || !password){
            return res.status(400).json({message:'some fields are missing'})        
        }

        //cheack if user already exists
        const isUserAlreadyExists = await User.findOne({email});
        if(isUserAlreadyExists){
            return res.status(400).json({message:'user already exists'})
        }else{
            //hashing the password
            const salt = await bcrypt.genSaltSync(10);
            const hashedPassword = await bcrypt.hashSync(password,salt);

            //jwt token
            const token = jwt.sign({email},'supersecret',{expiresIn:'365d'});

            //cresting new user
            await User.create({
                name,
                email,
                password:hashedPassword,
                token,
                role:'user'
            })
            return res.status(201).json({message:'User created successfuly'})
        }

    }catch(error){
        console.log(error);
        return res.status(500).json({message:'Internal server error'})
    }
})

//task-2 create a login route

app.post('/login',async(req,res)=>{
   try{
    const {email,password} = req.body;
     
    //cheak fiealdd
    if(!email || ! !password){
        return res.status(400).json({message:'some fields are missing'});
    }

    //user exist or not
    const user = await User.findOne({email});
    if(!user){
        return res.status(400).json({message:'User dose not exist'});
    }

    // compere the enter password with hashepassword
    const isPasswordMatched = await bcrypt.compareSync(password,user.password)
    if(isPasswordMatched){
        return res.status(400).json({message:"Password is incorrect"});
    }

    //successfully login
    return res.status(200).json({
        message:'user login succesfully',
        id:user._id,
        name:user.name,
        email:user.email,
        token:user.token,
        role:user.role

    })
   } catch(error){
    console.log(error);
    return res.status(500).json({message:'Internal server error'})
}
})

const PORT = 8080;

app.listen(PORT,()=>{
    console.log(`Server is connected to port ${PORT}`);
})