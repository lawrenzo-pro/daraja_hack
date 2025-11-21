require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mqtt = require('mqtt');

// --- APP CONFIGURATION ---
const app = express();
app.use(cors());
app.use(express.json()); // Parse JSON bodies

const SECRET_KEY = process.env.JWT_SECRET || "default_secret";

// --- DATABASE SETUP (SQLite) ---
// This will create a 'matatu.sqlite' file in your folder automatically
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: './matatu.sqlite',
    logging: false // Set to console.log to see raw SQL queries
});

// --- MODELS ---

// 1. User Model (Passengers, Crew, Owners)
const User = sequelize.define('User', {
    name: { type: DataTypes.STRING, allowNull: false },
    phone: { type: DataTypes.STRING, unique: true, allowNull: false },
    pinHash: { type: DataTypes.STRING, allowNull: false },
    balance: { type: DataTypes.FLOAT, defaultValue: 0.0 },
    role: { type: DataTypes.ENUM('PASSENGER', 'CREW', 'OWNER'), defaultValue: 'PASSENGER' }
});

// 2. Matatu Model
const Matatu = sequelize.define('Matatu', {
    plateNumber: { type: DataTypes.STRING, unique: true },
    route: { type: DataTypes.STRING }, // e.g., "Eldoret - Langas"
    sacco: { type: DataTypes.STRING }
});

// 3. NFC Tag Model (Linked to User)
const Tag = sequelize.define('Tag', {
    tagUid: { type: DataTypes.STRING, unique: true, allowNull: false },
    status: { type: DataTypes.ENUM('ACTIVE', 'BLOCKED'), defaultValue: 'ACTIVE' }
});

// 4. Transaction Model (History)
const Transaction = sequelize.define('Transaction', {
    type: { type: DataTypes.ENUM('DEPOSIT', 'TRANSFER', 'FARE_PAYMENT') },
    amount: { type: DataTypes.FLOAT, allowNull: false },
    reference: { type: DataTypes.STRING }, // M-Pesa Receipt or Phone Number
    description: { type: DataTypes.STRING }
});

// 5. Review Model (Ratings)
const Review = sequelize.define('Review', {
    rating: { type: DataTypes.INTEGER, allowNull: false, validate: { min: 1, max: 5 } },
    comment: { type: DataTypes.TEXT },
    tags: { type: DataTypes.STRING } // e.g. "Speeding, Clean, Loud Music"
});

// --- RELATIONSHIPS ---
User.hasMany(Tag);        Tag.belongsTo(User);
User.hasMany(Transaction); Transaction.belongsTo(User);
User.hasMany(Review);      Review.belongsTo(User);
Matatu.hasMany(Review);    Review.belongsTo(Matatu);

// --- INITIALIZATION ---
// Sync DB and Seed Eldoret Routes if empty
(async () => {
    await sequelize.sync({ force: false });
    console.log("✅ Database Synced");

    const count = await Matatu.count();
    if (count === 0) {
        await Matatu.bulkCreate([
            { plateNumber: "KCD 123A", route: "Eldoret Town - Langas", sacco: "Langas Shuttle" },
            { plateNumber: "KBK 888T", route: "Eldoret Town - Huruma", sacco: "Huruma Sacco" },
            { plateNumber: "KDG 456Y", route: "Eldoret Town - Kapsoya", sacco: "Kapsoya Line" },
            { plateNumber: "KDA 999Z", route: "Eldoret Town - Annex/Moi Uni", sacco: "Eldo-Uni" },
            { plateNumber: "KCC 321B", route: "Eldoret Town - Pioneer", sacco: "Pioneer Express" }
        ]);
        console.log("✅ Seeded Eldoret Matatu Routes");
    }
})();

// --- MIDDLEWARE ---

// 1. Verify JWT Token
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

// 2. Get Daraja Access Token
const getAccessToken = async (req, res, next) => {
    const key = process.env.MPESA_CONSUMER_KEY;
    const secret = process.env.MPESA_CONSUMER_SECRET;
    const auth = Buffer.from(`${key}:${secret}`).toString('base64');
    const url = process.env.MPESA_ENV === 'production' 
        ? 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
        : 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

    try {
        const response = await axios.get(url, { headers: { Authorization: `Basic ${auth}` } });
        req.accessToken = response.data.access_token;
        next();
    } catch (error) {
        console.error("Daraja Auth Error:", error.response ? error.response.data : error.message);
        res.status(401).json({ error: "Daraja Authentication Failed" });
    }
};

// --- HELPER FUNCTIONS ---
const formatPhone = (phone) => {
    if (phone.startsWith('0')) return '254' + phone.slice(1);
    if (phone.startsWith('+254')) return phone.slice(1);
    return phone;
};

const getTimestamp = () => {
    const date = new Date();
    return date.toISOString().replace(/[^0-9]/g, '').slice(0, 14);
};

const mqttClient = mqtt.connect('mqtt://localhost', {
    username: 'laurie',
    password: 'KeyM@nee17',
    clientId: 'matatu_backend_server_' + Math.random().toString(16).substr(2, 8)
});

// 2. On Connect
mqttClient.on('connect', () => {
    console.log("✅ Connected to MQTT Broker (User: laurie)");
    // Subscribe to all vehicle payment requests
    // Topic format: matatu/{plateNumber}/pay
    mqttClient.subscribe('matatu/+/pay'); 
});

// 3. Message Handler (The Core Logic)
mqttClient.on('message', async (topic, message) => {
    try {
        // Parse Topic & Payload
        // Topic: matatu/KCD123A/pay
        const plateNumber = topic.split('/')[1]; 
        const data = JSON.parse(message.toString()); // Expects: { "tagUid": "xx", "amount": 50 }
        
        console.log(`📡 Payment Request from ${plateNumber}:`, data);

        // A. Find the Tag & User
        const tag = await Tag.findOne({ 
            where: { tagUid: data.tagUid },
            include: User 
        });

        if (!tag || !tag.User) {
            console.log("❌ Unknown Tag");
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "ERROR", msg: "Invalid Card" }));
            return;
        }

        const user = tag.User;

        // B. Check Balance
        if (user.balance < data.amount) {
            console.log("❌ Insufficient Funds");
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "FAIL", msg: "Low Balance" }));
            // Optional: Trigger STK Push here automatically?
            return;
        }

        // C. Process Payment (Atomic Transaction)
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

        // D. Reply to Hardware (Unlock Turnstile / Print Ticket)
        console.log(`✅ Payment Approved: Ksh ${data.amount} from ${user.name}`);
        mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
            status: "SUCCESS", 
            msg: "Paid", 
            bal: user.balance - data.amount 
        }));

    } catch (err) {
        console.error("MQTT Error:", err.message);
    }
});
// --- API ROUTES ---

// 1. Authentication
app.post('/auth/signup', async (req, res) => {
    try {
        const { name, phone, pin } = req.body;
        const salt = await bcrypt.genSalt(10);
        const pinHash = await bcrypt.hash(pin, salt);
        const user = await User.create({ name, phone: formatPhone(phone), pinHash });
        res.json({ message: "User registered", userId: user.id });
    } catch (err) {
        res.status(400).json({ error: "User already exists" });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { phone, pin } = req.body;
        const user = await User.findOne({ where: { phone: formatPhone(phone) } });
        if (!user || !(await bcrypt.compare(pin, user.pinHash))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        const token = jwt.sign({ id: user.id, phone: user.phone }, SECRET_KEY, { expiresIn: '30d' });
        res.json({ message: "Login successful", token, user: { name: user.name, balance: user.balance } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Wallet: Token Transfer (Atomic Transaction)
app.post('/wallet/transfer', authenticate, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const { recipientPhone, amount } = req.body;
        const senderId = req.user.id;
        const val = parseFloat(amount);

        const sender = await User.findByPk(senderId);
        if (sender.balance < val) throw new Error("Insufficient Balance");

        const recipient = await User.findOne({ where: { phone: formatPhone(recipientPhone) } });
        if (!recipient) throw new Error("Recipient not found");

        await sender.decrement('balance', { by: val, transaction: t });
        await recipient.increment('balance', { by: val, transaction: t });

        await Transaction.create({ UserId: senderId, type: 'TRANSFER', amount: -val, description: `To ${recipient.name}`, reference: recipient.phone }, { transaction: t });
        await Transaction.create({ UserId: recipient.id, type: 'TRANSFER', amount: val, description: `From ${sender.name}`, reference: sender.phone }, { transaction: t });

        await t.commit();
        res.json({ message: "Transfer successful" });
    } catch (err) {
        await t.rollback();
        res.status(400).json({ error: err.message });
    }
});

// 3. Wallet: Buy Tokens (M-Pesa STK Push)
app.post('/wallet/deposit', authenticate, getAccessToken, async (req, res) => {
    const { amount } = req.body;
    const phone = req.user.phone; 
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
        "Amount": amount,
        "PartyA": phone,
        "PartyB": shortCode,
        "PhoneNumber": phone,
        "CallBackURL": callbackUrl,
        "AccountReference": "TokenBuy",
        "TransactionDesc": "Purchase Tokens"
    };

    try {
        const stkUrl = process.env.MPESA_ENV === 'production'
            ? 'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest'
            : 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';

        const response = await axios.post(stkUrl, payload, { headers: { Authorization: `Bearer ${req.accessToken}` } });
        res.json({ message: "STK Push Sent", data: response.data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. M-Pesa Callback Handler
app.post('/hooks/mpesa', async (req, res) => {
    try {
        const data = req.body.Body.stkCallback;
        if (data.ResultCode !== 0) return res.json({ ResultCode: 0, ResultDesc: "Cancelled" });

        const amount = data.CallbackMetadata.Item.find(o => o.Name === 'Amount').Value;
        const receipt = data.CallbackMetadata.Item.find(o => o.Name === 'MpesaReceiptNumber').Value;
        const phone = data.CallbackMetadata.Item.find(o => o.Name === 'PhoneNumber').Value.toString();

        const user = await User.findOne({ where: { phone: phone } });
        if (user) {
            await user.increment('balance', { by: amount });
            await Transaction.create({
                UserId: user.id, type: 'DEPOSIT', amount: amount, reference: receipt, description: "M-Pesa Deposit"
            });
            console.log(`💰 Credited Ksh ${amount} to ${user.name}`);
        }
        res.json({ ResultCode: 0, ResultDesc: "Accepted" });
    } catch (err) {
        console.error(err);
        res.json({ ResultCode: 0, ResultDesc: "Error" });
    }
});

// 5. Matatu: Get List with Ratings
app.get('/matatus', async (req, res) => {
    const matatus = await Matatu.findAll({
        include: [{ model: Review, attributes: ['rating'] }]
    });
    
    const data = matatus.map(m => {
        const json = m.toJSON();
        const total = json.Reviews.reduce((sum, r) => sum + r.rating, 0);
        const count = json.Reviews.length;
        json.averageRating = count > 0 ? (total / count).toFixed(1) : "New";
        delete json.Reviews; 
        return json;
    });
    res.json(data);
});

// 6. Matatu: Post Review
app.post('/matatus/:id/reviews', authenticate, async (req, res) => {
    try {
        const { rating, comment, tags } = req.body;
        await Review.create({
            UserId: req.user.id,
            MatatuId: req.params.id,
            rating, comment, tags
        });
        res.json({ message: "Review posted" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. User: Get Recent Activity
app.get('/wallet/activity', authenticate, async (req, res) => {
    const history = await Transaction.findAll({
        where: { UserId: req.user.id },
        order: [['createdAt', 'DESC']],
        limit: 10
    });
    res.json(history);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Matatu System running on port ${PORT}`));