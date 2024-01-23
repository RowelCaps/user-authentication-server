import express from 'express';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import pg from 'pg';
import cors from 'cors';
import jwt, { decode } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

const SALT_HASH = 10;

dotenv.config({path:'./.env'});

const app = express();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(cors({
    origin: 'https://rowelcaps.github.io',
    methods: "GET, POST, PUT, DELETE",
    credentials: true
}));

const db = new pg.Client({
    user:"avnadmin",
    host: "rowel-user-authentication-sample-user-authentication-sample.a.aivencloud.com",
    database: "defaultdb",
    password: "AVNS_NdUKrQH8KeIs8MW4Ut2",
    port:21541,
    ssl: {
        rejectUnauthorized: false, 
    },
})

db.connect()
.then(() => {
    console.log("Postgres Server is Now Connected");
}).catch((err) => {
    console.log(err);
});

app.get("/", function(req, res) {
    return res.json({message: "Hello"});
})

app.post('/token', async function(req,res) {

    const refreshToken = req.cookies.refreshToken;

    try{
        const result = await db.query("SELECT * from user_refresh_tokens WHERE refresh_token=$1", [hash]);

        if(result.rows.length <= 0) return res.sendStatus(401);

        const tokenInfo = result.rows[0];

        const currentDate = new Date();
        const expiryDate = tokenInfo.expiry_date;

        if(currentDate > expiryDate){
            return res.status(403).json({message: 'Token Expired!'});
        }

        bcrypt.compare(refreshToken, tokenInfo.refreshToken, (err, isMatch) => {
            if(err){
                return res.status(500).json({message: err});
            }

            if(!isMatch){
                return res.status(403);
            }

            jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY, (err, user) => {
    
                const accessToken = generateAccessToken({name: user.name})
                return res.json({accessToken: accessToken});
            });
        })

    } catch(error) {
        return res.status(500).json({message: error});
    }
});

app.get('/verify-authentication', async function(req, res) {

    const accessToken = req.cookies.accessToken;

    try{
        const decodedToken = await jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET_KEY);
        
        return res.status(200).json({success:true, message: 'verified User!'});

    } catch(error){
        const refreshResult = await refreshAccessTokens(req,res);

        if(!refreshResult.success) return res.status(refreshResult.status).json({success: false, message: refreshResult.message});

        res.cookie('accessToken', refreshResult.accessToken, {httpOnly: true, secure: true});
        return res.status(200).json({success:true, message: "Verified Client!"});
    }
});

app.post("/login", async function(req, res) {

    const user = { 
        email: req.body.email,
        password: req.body.password
    };

    const result = await db.query('SELECT email,password FROM user_data WHERE email=$1', [user.email]);


    if(result.rowCount <= 0) res.status(403).json({success: false, message: `Invalid Email`});

    const isPasswordMatch = await bcrypt.compare(user.password, result.rows[0].password);

    if(!isPasswordMatch)  res.status(400).json({success: false, message: `Invalid passsword`});

    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET_KEY);

    try{
        const currentDate = new Date();
        const expiryDate = new Date(currentDate);

        expiryDate.setMonth(expiryDate.getMonth() + 1);

        const formattedCurrentDate = currentDate.toISOString().split('T')[0];
        const formattedExpiryDate = expiryDate.toISOString().split('T')[0];

        bcrypt.hash(refreshToken, SALT_HASH, async function(err, hash) {

            const result = await db.query("INSERT INTO user_refresh_tokens (refresh_token, date_created, expiry_date) VALUES ($1,$2,$3)"
            , [hash, formattedCurrentDate, formattedExpiryDate]);
            
            if(result.rowCount > 0){
                res.cookie('accessToken', accessToken, {httpOnly: true, secure: true});
                res.cookie('refreshToken', refreshToken, {httpOnly: true, secure: true});
        
                return res.status(200).json({success:true, accessToken: accessToken, refreshToken: refreshToken});
            } else {
                return res.sendStatus(403);
            }
        });

    } catch(err) {
        return res.sendStatus(500).json({success: false, message: ""});
    }
});

app.post("/register", async function(req, res) {

    const userData = {
        name: req.body.name,
        email: req.body.email,
        password: req.body.password
    }

    const userExistResult = await db.query('SELECT * from user_data WHERE email=$1', [userData.email]);

    if(userExistResult.rowCount > 0) {
        return res.status(403).json({success: false, message: "Email has been taken!"});
    }

    bcrypt.hash(userData.password, SALT_HASH, async function(err, hash) {

        try{
            const result = await db.query("INSERT INTO user_data (name,email, password) VALUES ($1,$2,$3)",
             [userData.name, userData.email, hash]);

             if(result.rowCount <= 0){
                return res.status(500).json({success: true, message: "Failed to register!"});
             }

             const accessToken = generateAccessToken(userData.email);
            const refreshToken = jwt.sign(userData.email, process.env.REFRESH_TOKEN_SECRET_KEY);

            try{
                const currentDate = new Date();
                const expiryDate = new Date(currentDate);

                expiryDate.setMonth(expiryDate.getMonth() + 1);

                const formattedCurrentDate = currentDate.toISOString().split('T')[0];
                const formattedExpiryDate = expiryDate.toISOString().split('T')[0];

                bcrypt.hash(refreshToken, SALT_HASH, async function(err, hash) {

                    const result = await db.query("INSERT INTO user_refresh_tokens (refresh_token, date_created, expiry_date) VALUES ($1,$2,$3)"
                    , [hash, formattedCurrentDate, formattedExpiryDate]);
                
                    if(result.rowCount > 0){
                        return res.status(200).json({success: true, accessToken: accessToken, refreshToken: refreshToken});
                    } else {
                        return res.sendStatus(403);
                    }
                });

            } catch(err) {
                return res.status(500).json({success: true, message: "Failed to register!"});
            }

        } catch(err) {
            console.log(err);
            return res.status(500).json({success: true, message: "Failed to register!"});
        }
    });
});



app.get("/user", async function(req, res) {
    const accessToken = req.cookies.accessToken;

    if(!accessToken) return res.status(403).json({success:false, message: "Invalid Access Token"});

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET_KEY, async (err,user) => {
        const result = await db.query("SELECT name,email from user_data WHERE email=$1", [user.email]);

        if(result.rowCount <= 0) return res.status(403).json({success:false, message: "Invalid Access Token"});

        const userData = result.rows[0];
        return res.status(200).json({success: true, userData: userData});
    });
});

app.get("/testServer", async function(req,res) {
    return res.json({message: "server is live"});
  });

app.post('/logout', async function(req,res){
    const refreshToken = req.cookies.refreshToken;

    const hashedToken = await bcrypt.hash(refreshToken, SALT_HASH);
    console.log("fuck you");
    const result = await db.query('DELETE FROM user_refresh_tokens WHERE refresh_token=$1', [hashedToken]);
    console.log("fuck you");

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    return res.status(200).json({success: true, message:"Logout Success"});
});

function generateAccessToken(userData){
    return jwt.sign({email: userData.email}, process.env.ACCESS_TOKEN_SECRET_KEY, {expiresIn: '10m'});
}

async function refreshAccessTokens(req, res){
    const refreshToken = req.cookies.refreshToken;

    try{
        const refreshTokenHashed = await bcrypt.hash(refreshToken, SALT_HASH);
        const result = await db.query("SELECT * from user_refresh_tokens WHERE refresh_token=$1", [refreshTokenHashed]);

        if(result.rows.length <= 0) return {status: 503, success: false,message: "Refresh Token Invalid"};

        const tokenInfo = result.rows[0];

        const currentDate = new Date();
        const expiryDate = tokenInfo.expiry_date;

        if(currentDate > expiryDate){
            return {status: 403, success: false, message: 'Token Expired!'};
        }

        if(refreshTokenHashed != tokenInfo.refresh_token){
            return {status: 403, success: false, message: 'Token could not be found!'};
        }

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY, (err, user) => {

            const accessToken = generateAccessToken({email: user.email})
            return {success: true, accessToken: accessToken};
        });

    } catch(error) {
        return {success: false, message: "Internal Server Error"};
    }
}

app.listen(process.env.SERVER_PORT, () => {
    console.log(`Listening to PORT ${process.env.SERVER_PORT}`);
})