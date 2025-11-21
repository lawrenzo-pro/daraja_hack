require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mqtt = require('mqtt');

// --- CONFIGURATION ---
const app = express();
app.use(cors());
app.use(express.json());
const SECRET_KEY = process.env.JWT_SECRET || "secret";

// --- DB SETUP ---
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './matatu.sqlite',
    logging: false
});

// --- MODELS ---
const User = sequelize.define('User', {
    name: { type: DataTypes.STRING, allowNull: false },
    phone: { type: DataTypes.STRING, unique: true, allowNull: false }, // Format: 2547...
    pinHash: { type: DataTypes.STRING, allowNull: false },
    balance: { type: DataTypes.FLOAT, defaultValue: 0.0 },
});

const Tag = sequelize.define('Tag', {
    tagUid: { type: DataTypes.STRING, unique: true },
    status: { type: DataTypes.ENUM('ACTIVE', 'BLOCKED'), defaultValue: 'ACTIVE' }
});

const Transaction = sequelize.define('Transaction', {
    type: { type: DataTypes.ENUM('DEPOSIT', 'FARE_PAYMENT') },
    amount: { type: DataTypes.FLOAT },
    reference: { type: DataTypes.STRING },
    description: { type: DataTypes.STRING }
});

User.hasMany(Tag); Tag.belongsTo(User);
User.hasMany(Transaction); Transaction.belongsTo(User);

// Sync DB
(async () => { await sequelize.sync(); console.log("✅ DB Synced"); })();

// ============================================================
// 🛠️ HELPER FUNCTIONS (Standalone)
// ============================================================

const getTimestamp = () => new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);

// 1. Internal Token Generator (No Express Req/Res)
const generateTokenInternal = async () => {
    const key = process.env.MPESA_CONSUMER_KEY;
    const secret = process.env.MPESA_CONSUMER_SECRET;
    const auth = Buffer.from(`${key}:${secret}`).toString('base64');
    const url = process.env.MPESA_ENV === 'production' 
        ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
        : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

    const response = await axios.get(url, { headers: { Authorization: `Basic ${auth}` } });
    return response.data.access_token;
};

// 2. Standalone STK Push Function
const triggerStkPush = async (phone, amount, accountRef = "AutoTopUp") => {
    try {
        const token = await generateTokenInternal();
        const shortCode = process.env.MPESA_SHORTCODE;
        const passkey = process.env.MPESA_PASSKEY;
        const timestamp = getTimestamp();
        const password = Buffer.from(shortCode + passkey + timestamp).toString('base64');
        const callbackUrl = `${process.env.MPESA_CALLBACK_URL}/hooks/mpesa`;

        const payload = {
            "BusinessShortCode": shortCode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": Math.ceil(amount), // Ensure whole numbers
            "PartyA": phone,
            "PartyB": shortCode,
            "PhoneNumber": phone,
            "CallBackURL": callbackUrl,
            "AccountReference": accountRef,
            "TransactionDesc": "Low Balance Topup"
        };

        const stkUrl = process.env.MPESA_ENV === 'production' 
            ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest' 
            : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';

        await axios.post(stkUrl, payload, { headers: { Authorization: `Bearer ${token}` } });
        console.log(`📲 STK Push sent to ${phone} for Ksh ${amount}`);
        return true;
    } catch (error) {
        console.error("❌ STK Push Error:", error.response ? error.response.data : error.message);
        return false;
    }
};

// ============================================================
// 🚀 MQTT LOGIC (The Updated Part)
// ============================================================

const mqttClient = mqtt.connect('mqtt://localhost', {
    username: 'laurie',
    password: 'KeyM@nee17',
    clientId: 'backend_server'
});

mqttClient.on('connect', () => {
    console.log("✅ MQTT Connected");
    mqttClient.subscribe('matatu/+/pay');
});

mqttClient.on('message', async (topic, message) => {
    try {
        const plateNumber = topic.split('/')[1];
        const data = JSON.parse(message.toString()); // { "tagUid": "...", "amount": 50 }
        
        console.log(`📡 Scan from ${plateNumber}:`, data);

        // 1. Find User
        const tag = await Tag.findOne({ where: { tagUid: data.tagUid }, include: User });

        if (!tag || !tag.User) {
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "ERROR", msg: "Unknown Card" }));
            return;
        }

        const user = tag.User;

        // 2. Check Balance
        if (user.balance < data.amount) {
            console.log(`⚠️ Low Balance (${user.balance}). Fare is ${data.amount}. Triggering STK...`);
            
            // --- NEW LOGIC: AUTO STK PUSH ---
            // We ask for the EXACT fare amount so they can pay immediately
            const sent = await triggerStkPush(user.phone, data.amount, plateNumber);

            if (sent) {
                // Tell Matatu Screen to notify user
                mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
                    status: "INFO", 
                    msg: "Check Phone PIN", 
                    bal: user.balance 
                }));
            } else {
                mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
                    status: "FAIL", 
                    msg: "M-Pesa Error" 
                }));
            }
            return;
        }

        // 3. Process Successful Payment
        await sequelize.transaction(async (t) => {
            await user.decrement('balance', { by: data.amount, transaction: t });
            await Transaction.create({
                UserId: user.id,
                type: 'FARE_PAYMENT',
                amount: -data.amount,
                reference: plateNumber,
                description: `Fare`
            }, { transaction: t });
        });

        console.log(`✅ Paid Ksh ${data.amount}`);
        mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
            status: "SUCCESS", 
            msg: "Paid", 
            bal: user.balance - data.amount 
        }));

    } catch (err) {
        console.error("MQTT Logic Error:", err);
    }
});

// ============================================================
// 🌐 EXPRESS ROUTES (Callbacks & Auth)
// ============================================================

// M-Pesa Callback (Funds the wallet)
app.post('/hooks/mpesa', async (req, res) => {
    try {
        const data = req.body.Body.stkCallback;
        if (data.ResultCode !== 0) return res.json({ ResultCode: 0 });

        const amount = data.CallbackMetadata.Item.find(o => o.Name === 'Amount').Value;
        const phone = data.CallbackMetadata.Item.find(o => o.Name === 'PhoneNumber').Value.toString();

        const user = await User.findOne({ where: { phone } });
        if (user) {
            await user.increment('balance', { by: amount });
            await Transaction.create({ UserId: user.id, type: 'DEPOSIT', amount: amount, reference: "Auto-MPesa", description: "Deposit" });
            console.log(`💰 Wallet Funded: ${amount}`);
        }
        res.json({ ResultCode: 0 });
    } catch (err) { res.json({ ResultCode: 0 }); }
});

// Simple Signup to test
app.post('/auth/signup', async (req, res) => {
    try {
        const { name, phone, pin } = req.body;
        const pinHash = await bcrypt.hash(pin, 10);
        // Ensure phone is stored as 2547...
        const formattedPhone = phone.startsWith('0') ? '254' + phone.slice(1) : phone;
        const user = await User.create({ name, phone: formattedPhone, pinHash });
        res.json({ userId: user.id });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// Enroll Tag
app.post('/tags/enroll', async (req, res) => {
    try {
        await Tag.create({ tagUid: req.body.tagUid, UserId: req.body.userId });
        res.json({ msg: "Enrolled" });
    } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/auth/login', async (req, res) => {
    try {
        const { phone, pin } = req.body;
        // Format incoming phone to match DB format (254...)
        const formattedPhone = phone.startsWith('0') ? '254' + phone.slice(1) : phone;

        const user = await User.findOne({ where: { phone: formattedPhone } });
        
        if (!user || !(await bcrypt.compare(pin, user.pinHash))) {
            return res.status(401).json({ error: "Invalid Phone or PIN" });
        }

        // Generate Token
        const token = jwt.sign({ id: user.id, phone: user.phone }, SECRET_KEY, { expiresIn: '30d' });
        res.json({ message: "Login successful", token, user: { name: user.name, balance: user.balance } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
app.get('/wallet/balance', authenticate, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        res.json({ balance: user.balance, name: user.name });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. Get Registered Tags
app.get('/tags', authenticate, async (req, res) => {
    try {
        const tags = await Tag.findAll({ where: { UserId: req.user.id } });
        res.json(tags);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. Transfer Tokens to Another User
app.post('/wallet/transfer', authenticate, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const { recipientPhone, amount } = req.body;
        const val = parseFloat(amount);
        const senderId = req.user.id;

        if (isNaN(val) || val <= 0) throw new Error("Invalid amount");

        // Validate Sender
        const sender = await User.findByPk(senderId);
        if (sender.balance < val) throw new Error("Insufficient Balance");

        // Validate Recipient
        const formattedRecipientPhone = formatPhone(recipientPhone);
        if (formattedRecipientPhone === sender.phone) throw new Error("Cannot transfer to self");
        
        const recipient = await User.findOne({ where: { phone: formattedRecipientPhone } });
        if (!recipient) throw new Error("Recipient not found");

        // Execute Atomic Transfer
        await sender.decrement('balance', { by: val, transaction: t });
        await recipient.increment('balance', { by: val, transaction: t });

        // Log Transactions
        await Transaction.create({
            UserId: senderId,
            type: 'TRANSFER',
            amount: -val,
            reference: recipient.phone,
            description: `Transfer to ${recipient.name}`
        }, { transaction: t });

        await Transaction.create({
            UserId: recipient.id,
            type: 'TRANSFER',
            amount: val,
            reference: sender.phone,
            description: `Received from ${sender.name}`
        }, { transaction: t });

        await t.commit();
        res.json({ message: "Transfer successful", newBalance: sender.balance - val });
    } catch (err) {
        await t.rollback();
        res.status(400).json({ error: err.message });
    }
});
app.listen(3000, () => console.log("🚀 Server Running"));