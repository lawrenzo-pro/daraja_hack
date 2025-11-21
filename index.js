require('dotenv').config();
const express = require('express');
const axios = require('axios');
let app =express()
app.use(express.json())
const isProduction = process.env.MPESA_ENV === 'production';

const urls = {
    token: isProduction
        ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
        : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
    stk: isProduction
        ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
        : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
};
const shortCode = 174379;
const passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919";
const stkUrl = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
// --- AUTH MIDDLEWARE ---
const getAccessToken = async (req, res, next) => {
    const key = process.env.MPESA_CONSUMER_KEY;
    const secret = process.env.MPESA_CONSUMER_SECRET;

    if (!key || !secret) {
        return res.status(500).json({ 
            error: "Missing Credentials", 
            message: "Please check your .env file" 
        });
    }

    // 1. Construct the Basic Auth Header correctly
    // The string must be "Key:Secret" encoded to Base64
    const auth = Buffer.from(`${key}:${secret}`).toString('base64');

    try {
        const response = await axios.get(urls.token, {
            headers: {
                Authorization: `Basic ${auth}`,
            },
        });

        // 2. Attach the token to the request object
        req.accessToken = response.data.access_token;
        console.log("✅ Token Generated Successfully:", req.accessToken);
        next();

    } catch (error) {
        console.error("❌ Auth Failed:", error.response ? error.response.data : error.message);
        res.status(401).json({ 
            error: "Authentication Failed", 
            details: error.response ? error.response.data : error.message 
        });
    }
}
app.get('/test-auth', getAccessToken, (req, res) => {
    res.json({ message: "Authentication works!", token: req.accessToken });
});
const getTimestamp = () => {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-based
    const day = String(date.getDate()).padStart(2, '0');
    const hour = String(date.getHours()).padStart(2, '0');
    const minute = String(date.getMinutes()).padStart(2, '0');
    const second = String(date.getSeconds()).padStart(2, '0');
    
    return `${year}${month}${day}${hour}${minute}${second}`;
};

// --- ROUTE: SEND STK PUSH ---
app.get('/stk-push', getAccessToken, async (req, res) => {
    const phoneNumber = "254790232089" 
    const amount  = "3000"
    
    // 1. Get Config from .env
    const shortCode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    const callbackUrl = process.env.MPESA_CALLBACK_URL; // Ensure this is your Ngrok URL


    // 2. Generate Timestamp & Password
    const timestamp = getTimestamp();
    const password = Buffer.from(shortCode + passkey + timestamp).toString('base64');

    // 3. Construct the Payload
    const payload = {
        "BusinessShortCode": shortCode,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phoneNumber,      // Phone sending the money
        "PartyB": shortCode,        // The Paybill receiving the money
        "PhoneNumber": phoneNumber, // Same as PartyA
        "CallBackURL": callbackUrl,
        "AccountReference": "TestPayment",
        "TransactionDesc": "Test Payment"
    };

    // 4. Send Request
    try {
        const response = await axios.post(urls.stk, payload, {
            headers: {
                Authorization: `Bearer ${req.accessToken}`,
            },
        });
        
        console.log("✅ STK Push Sent:", response.data);
        res.json(response.data);

    } catch (error) {
        console.error("❌ STK Push Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ 
            error: "STK Push Failed", 
            details: error.response ? error.response.data : error.message 
        });
    }
});
app.post("/callback", (req,res) => {
    console.log(req.body.Body.stkCallback)
    //console.log(res)
})
app.get("/hello", (req,res) => {
    res.send("Hello!")
})
app.listen(3000)