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
    phone: { type: DataTypes.STRING, unique: true, allowNull: false }, 
    pinHash: { type: DataTypes.STRING, allowNull: false },
    balance: { type: DataTypes.FLOAT, defaultValue: 0.0 },
});

const Tag = sequelize.define('Tag', {
    tagUid: { type: DataTypes.STRING, unique: true },
    status: { type: DataTypes.ENUM('ACTIVE', 'BLOCKED'), defaultValue: 'ACTIVE' }
});

// Re-added Matatu Model
const Matatu = sequelize.define('Matatu', {
    plateNumber: { type: DataTypes.STRING, unique: true },
    route: { type: DataTypes.STRING }, // e.g., "Eldoret - Langas"
    sacco: { type: DataTypes.STRING }
});

// Re-added Review Model
const Review = sequelize.define('Review', {
    rating: { type: DataTypes.INTEGER, allowNull: false, validate: { min: 1, max: 5 } },
    comment: { type: DataTypes.TEXT },
    tags: { type: DataTypes.STRING } 
});

const Transaction = sequelize.define('Transaction', {
    type: { type: DataTypes.ENUM('DEPOSIT', 'FARE_PAYMENT', 'TRANSFER') },
    amount: { type: DataTypes.FLOAT },
    reference: { type: DataTypes.STRING },
    description: { type: DataTypes.STRING }
});

// --- RELATIONSHIPS ---
User.hasMany(Tag);        Tag.belongsTo(User);
User.hasMany(Transaction); Transaction.belongsTo(User);
User.hasMany(Review);      Review.belongsTo(User);
Matatu.hasMany(Review);    Review.belongsTo(Matatu);

// --- DB INIT ---
(async () => { 
    await sequelize.sync({ force: false }); 
    console.log("✅ DB Synced");

    // Seed Matatus if empty
    if (await Matatu.count() === 0) {
        await Matatu.bulkCreate([
            { plateNumber: "KCD 123A", route: "Eldoret Town - Langas", sacco: "Langas Shuttle" },
            { plateNumber: "KBK 888T", route: "Eldoret Town - Huruma", sacco: "Huruma Sacco" },
            { plateNumber: "KDG 456Y", route: "Eldoret Town - Kapsoya", sacco: "Kapsoya Line" },
            { plateNumber: "KDA 999Z", route: "Eldoret Town - Annex/Moi Uni", sacco: "Eldo-Uni" }
        ]);
        console.log("✅ Seeded Matatus");
    }
})();

// ============================================================
// 🛠️ HELPER FUNCTIONS
// ============================================================

const getTimestamp = () => new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);

const formatPhone = (phone) => {
    let p = phone.toString().replace(/\s+/g, '');
    if (p.startsWith('+')) p = p.slice(1);
    if (p.startsWith('0')) p = '254' + p.slice(1);
    return p;
};

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
            "Amount": Math.ceil(amount),
            "PartyA": formatPhone(phone),
            "PartyB": shortCode,
            "PhoneNumber": formatPhone(phone),
            "CallBackURL": callbackUrl,
            "AccountReference": accountRef,
            "TransactionDesc": "Topup"
        };

        const stkUrl = process.env.MPESA_ENV === 'production' 
            ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest' 
            : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';

        await axios.post(stkUrl, payload, { headers: { Authorization: `Bearer ${token}` } });
        console.log(`📲 STK Push sent to ${phone}`);
        return true;
    } catch (error) {
        console.error("❌ STK Push Error:", error.response ? error.response.data : error.message);
        return false;
    }
};

// ============================================================
// 🚀 MQTT LOGIC
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
        const data = JSON.parse(message.toString()); 
        console.log(`📡 Scan from ${plateNumber}:`, data);

        const tag = await Tag.findOne({ where: { tagUid: data.tagUid }, include: User });

        if (!tag || !tag.User) {
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "ERROR", msg: "Unknown Card" }));
            return;
        }

        const user = tag.User;

        // Check Balance
        if (user.balance < data.amount) {
            console.log(`⚠️ Low Balance. Triggering STK...`);
            const sent = await triggerStkPush(user.phone, data.amount, plateNumber);
            
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
                status: sent ? "INFO" : "FAIL", 
                msg: sent ? "Check Phone PIN" : "M-Pesa Error", 
                bal: user.balance 
            }));
            return;
        }

        // Process Payment
        await sequelize.transaction(async (t) => {
            await user.decrement('balance', { by: data.amount, transaction: t });
            await Transaction.create({
                UserId: user.id,
                type: 'FARE_PAYMENT',
                amount: -data.amount,
                reference: plateNumber,
                description: `Fare for ${plateNumber}`
            }, { transaction: t });
        });
        
        await user.reload(); 
        console.log(`✅ Paid Ksh ${data.amount}. New Bal: ${user.balance}`);
        
        mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
            status: "SUCCESS", 
            msg: "Paid", 
            bal: user.balance
        }));

    } catch (err) {
        console.error("MQTT Logic Error:", err);
    }
});

// ============================================================
// 🌐 EXPRESS ROUTES
// ============================================================

const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user;
        next();
    });
};

// --- WALLET & USER ENDPOINTS ---

// 1. Get Balance
app.get('/wallet/balance', authenticate, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id);
        res.json({ balance: user.balance, name: user.name });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. Get Recent Activity (RESTORED)
app.get('/wallet/activity', authenticate, async (req, res) => {
    try {
        const history = await Transaction.findAll({
            where: { UserId: req.user.id },
            order: [['createdAt', 'DESC']],
            limit: 15
        });
        res.json(history);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 3. Manual Deposit (RESTORED)
app.post('/wallet/deposit', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        if(!amount) return res.status(400).json({ error: "Amount required" });

        const sent = await triggerStkPush(req.user.phone, amount, "AppDeposit");
        if(sent) res.json({ message: "STK Push Sent" });
        else res.status(500).json({ error: "Failed to send STK Push" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. Transfer
app.post('/wallet/transfer', authenticate, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const { recipientPhone, amount } = req.body;
        const val = parseFloat(amount);
        const senderId = req.user.id;

        if (isNaN(val) || val <= 0) throw new Error("Invalid amount");

        const sender = await User.findByPk(senderId);
        if (sender.balance < val) throw new Error("Insufficient Balance");

        const formattedRecipientPhone = formatPhone(recipientPhone);
        if (formattedRecipientPhone === sender.phone) throw new Error("Cannot transfer to self");
        
        const recipient = await User.findOne({ where: { phone: formattedRecipientPhone } });
        if (!recipient) throw new Error("Recipient not found");

        await sender.decrement('balance', { by: val, transaction: t });
        await recipient.increment('balance', { by: val, transaction: t });

        await Transaction.create({ UserId: senderId, type: 'TRANSFER', amount: -val, reference: recipient.phone, description: `Transfer to ${recipient.name}` }, { transaction: t });
        await Transaction.create({ UserId: recipient.id, type: 'TRANSFER', amount: val, reference: sender.phone, description: `Received from ${sender.name}` }, { transaction: t });

        await t.commit();
        res.json({ message: "Transfer successful", newBalance: sender.balance - val });
    } catch (err) {
        await t.rollback();
        res.status(400).json({ error: err.message });
    }
});

// --- MATATU & REVIEWS (RESTORED) ---

// 5. Get Matatus
app.get('/matatus', async (req, res) => {
    try {
        const matatus = await Matatu.findAll({
            include: [{ model: Review, attributes: ['rating'] }]
        });
        
        const data = matatus.map(m => {
            const json = m.toJSON();
            const total = json.Reviews.reduce((sum, r) => sum + r.rating, 0);
            const count = json.Reviews.length;
            json.averageRating = count > 0 ? (total / count).toFixed(1) : "New";
            json.reviewCount = count;
            delete json.Reviews;
            return json;
        });
        res.json(data);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 6. Post Review
app.post('/matatus/:id/reviews', authenticate, async (req, res) => {
    try {
        const { rating, comment, tags } = req.body;
        await Review.create({
            UserId: req.user.id,
            MatatuId: req.params.id,
            rating, comment, tags
        });
        res.json({ message: "Review posted" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- TAGS & AUTH ---

// Get Tags
app.get('/tags', authenticate, async (req, res) => {
    try {
        const tags = await Tag.findAll({ where: { UserId: req.user.id } });
        res.json(tags);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Enroll Tag
app.post('/tags/enroll', authenticate, async (req, res) => {
    try {
        await Tag.create({ tagUid: req.body.tagUid, UserId: req.user.id });
        res.json({ msg: "Enrolled" });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// Signup
app.post('/auth/signup', async (req, res) => {
    try {
        const { name, phone, pin } = req.body;
        const pinHash = await bcrypt.hash(pin, 10);
        const user = await User.create({ name, phone: formatPhone(phone), pinHash });
        res.json({ userId: user.id });
    } catch (e) { res.status(400).json({ error: e.message }); }
});

// Login
app.post('/auth/login', async (req, res) => {
    try {
        const { phone, pin } = req.body;
        const user = await User.findOne({ where: { phone: formatPhone(phone) } });
        if (!user || !(await bcrypt.compare(pin, user.pinHash))) {
            return res.status(401).json({ error: "Invalid Phone or PIN" });
        }
        const token = jwt.sign({ id: user.id, phone: user.phone }, SECRET_KEY, { expiresIn: '30d' });
        res.json({ message: "Login successful", token, user: { name: user.name, balance: user.balance } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- M-PESA CALLBACK ---
app.post('/hooks/mpesa', async (req, res) => {
    console.log("📥 M-Pesa Callback Received");
    try {
        const data = req.body.Body.stkCallback;
        
        if (data.ResultCode !== 0) {
            console.log("❌ M-Pesa Transaction Failed:", data.ResultDesc);
            return res.json({ ResultCode: 0 });
        }

        const amount = data.CallbackMetadata.Item.find(o => o.Name === 'Amount').Value;
        const rawPhone = data.CallbackMetadata.Item.find(o => o.Name === 'PhoneNumber').Value.toString();
        const receipt = data.CallbackMetadata.Item.find(o => o.Name === 'MpesaReceiptNumber').Value;
        const phone = formatPhone(rawPhone);

        console.log(`Processing Deposit: Ksh ${amount} for ${phone}`);

        const user = await User.findOne({ where: { phone } });
        
        if (user) {
            await user.increment('balance', { by: amount });
            await Transaction.create({ 
                UserId: user.id, 
                type: 'DEPOSIT', 
                amount: amount, 
                reference: receipt, 
                description: "M-Pesa Deposit" 
            });
            
            await user.reload(); 
            console.log(`✅ Wallet Updated! New Balance: ${user.balance}`);
        } else {
            console.error(`⚠️ User Not Found! Phone in DB does not match ${phone}`);
        }
        
        res.json({ ResultCode: 0 });
    } catch (err) { 
        console.error("Callback Error:", err);
        res.json({ ResultCode: 0 }); 
    }
});

app.listen(3000, () => console.log("🚀 Server Running"));