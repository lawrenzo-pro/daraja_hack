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
app.use(express.urlencoded({ extended: true }));
app.use(express.json({
    verify: (req, res, buf) => {
        if (req.originalUrl === '/hooks/payhero') {
            req.rawBody = buf.toString('utf8');
        }
    }
}));
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
    role: { type: DataTypes.ENUM('PASSENGER', 'ADMIN'), defaultValue: 'PASSENGER' }
});

const Tag = sequelize.define('Tag', {
    tagUid: { type: DataTypes.STRING, unique: true },
    status: { type: DataTypes.ENUM('ACTIVE', 'BLOCKED'), defaultValue: 'ACTIVE' }
});

const Route = sequelize.define('Route', {
    name: { type: DataTypes.STRING, unique: true, allowNull: false },
    origin: { type: DataTypes.STRING, allowNull: false },
    destination: { type: DataTypes.STRING, allowNull: false },
    baseFare: { type: DataTypes.FLOAT, defaultValue: 0 },
    status: { type: DataTypes.ENUM('ACTIVE', 'INACTIVE'), defaultValue: 'ACTIVE' }
});

const Driver = sequelize.define('Driver', {
    name: { type: DataTypes.STRING, allowNull: false },
    phone: { type: DataTypes.STRING, unique: true },
    licenseNumber: { type: DataTypes.STRING, unique: true },
    status: { type: DataTypes.ENUM('ACTIVE', 'INACTIVE'), defaultValue: 'ACTIVE' }
});

const Matatu = sequelize.define('Matatu', {
    plateNumber: { type: DataTypes.STRING, unique: true, allowNull: false },
    route: { type: DataTypes.STRING },
    sacco: { type: DataTypes.STRING },
    status: { type: DataTypes.ENUM('ACTIVE', 'INACTIVE'), defaultValue: 'ACTIVE' }
});

const MatatuAdminRecipient = sequelize.define('MatatuAdminRecipient', {
    MatatuId: { type: DataTypes.INTEGER, allowNull: false, unique: true },
    adminPhone: { type: DataTypes.STRING, allowNull: false }
});

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

const PayoutSchedule = sequelize.define('PayoutSchedule', {
    frequency: { type: DataTypes.ENUM('DAILY', 'WEEKLY', 'MONTHLY'), defaultValue: 'WEEKLY' },
    payoutPercentage: { type: DataTypes.FLOAT, defaultValue: 0.8 },
    fixedAmount: { type: DataTypes.FLOAT },
    nextPayoutAt: { type: DataTypes.DATE, allowNull: false },
    lastPayoutAt: { type: DataTypes.DATE },
    status: { type: DataTypes.ENUM('ACTIVE', 'PAUSED', 'COMPLETED'), defaultValue: 'ACTIVE' },
    notes: { type: DataTypes.TEXT }
});

// --- RELATIONSHIPS ---
User.hasMany(Tag);        Tag.belongsTo(User);
User.hasMany(Transaction); Transaction.belongsTo(User);
User.hasMany(Review);      Review.belongsTo(User);
Matatu.hasMany(Review);    Review.belongsTo(Matatu);
Route.hasMany(Matatu);     Matatu.belongsTo(Route);
Driver.hasMany(Matatu);    Matatu.belongsTo(Driver);
Matatu.hasMany(Transaction); Transaction.belongsTo(Matatu);
Matatu.hasOne(MatatuAdminRecipient, { as: 'RecipientConfig', foreignKey: 'MatatuId' });
MatatuAdminRecipient.belongsTo(Matatu, { foreignKey: 'MatatuId' });
User.hasMany(MatatuAdminRecipient, { as: 'ManagedMatatuRecipients', foreignKey: 'adminPhone', sourceKey: 'phone' });
MatatuAdminRecipient.belongsTo(User, { as: 'AdminUser', foreignKey: 'adminPhone', targetKey: 'phone' });
Driver.hasMany(PayoutSchedule); PayoutSchedule.belongsTo(Driver);
Matatu.hasMany(PayoutSchedule); PayoutSchedule.belongsTo(Matatu);
Route.hasMany(PayoutSchedule); PayoutSchedule.belongsTo(Route);

// --- DB INIT ---
(async () => { 
    const allowAlterSync = process.env.DB_ALTER_SYNC === 'true';

    try {
        if (allowAlterSync) {
            await sequelize.sync({ alter: true });
            console.log("✅ DB Synced (alter mode)");
        } else {
            await sequelize.sync();
            console.log("✅ DB Synced (safe mode)");
        }
    } catch (syncError) {
        console.error("❌ DB Sync failed in current mode:", syncError.message);

        if (allowAlterSync) {
            console.log("↩️ Retrying DB sync in safe mode to avoid SQLite FK drop issues...");
            await sequelize.sync();
            console.log("✅ DB Synced (safe fallback)");
        } else {
            throw syncError;
        }
    }

    const seedMatatus = [
        { plateNumber: "KCD 123A", route: "Eldoret Town - Langas", sacco: "Langas Shuttle" },
        { plateNumber: "KBK 888T", route: "Eldoret Town - Huruma", sacco: "Huruma Sacco" },
        { plateNumber: "KDG 456Y", route: "Eldoret Town - Kapsoya", sacco: "Kapsoya Line" },
        { plateNumber: "KDA 999Z", route: "Eldoret Town - Annex/Moi Uni", sacco: "Eldo-Uni" }
    ];

    for (const seed of seedMatatus) {
        const [routeRecord] = await Route.findOrCreate({
            where: { name: seed.route },
            defaults: {
                name: seed.route,
                origin: seed.route.split(' - ')[0].trim(),
                destination: seed.route.split(' - ').slice(1).join(' - ').trim() || seed.route
            }
        });

        const [matatuRecord, created] = await Matatu.findOrCreate({
            where: { plateNumber: seed.plateNumber },
            defaults: {
                plateNumber: seed.plateNumber,
                route: seed.route,
                sacco: seed.sacco,
                RouteId: routeRecord.id
            }
        });

        if (!created && (!matatuRecord.RouteId || matatuRecord.route !== seed.route || matatuRecord.sacco !== seed.sacco)) {
            await matatuRecord.update({ route: seed.route, sacco: seed.sacco, RouteId: routeRecord.id });
        }
    }

    console.log("✅ Seeded Matatus and Routes");
})();

// ============================================================
// 🛠️ HELPER FUNCTIONS
// ============================================================

const formatPhone = (phone) => {
    let p = phone.toString().replace(/\s+/g, '');
    if (p.startsWith('+')) p = p.slice(1);
    if (p.startsWith('0')) p = '254' + p.slice(1);
    return p;
};

const formatPhoneForPayhero = (phone) => {
    const normalized = formatPhone(phone);
    if (normalized.startsWith('254')) return `0${normalized.slice(3)}`;
    return normalized;
};

const triggerStkPush = async (phone, amount, accountRef = "AutoTopUp") => {
    try {
        const authToken = process.env.PAYHERO_AUTH_TOKEN;
        const channelId = process.env.PAYHERO_CHANNEL_ID;
        const provider = process.env.PAYHERO_PROVIDER || 'm-pesa';
        const callbackBase = (process.env.PAYHERO_CALLBACK_URL || '').replace(/\/+$/, '');
        const callbackUrl = `${callbackBase}/hooks/payhero`;

        const payload = {
            amount: Math.ceil(amount),
            phone_number: formatPhoneForPayhero(phone),
            channel_id: parseInt(channelId, 10),
            provider,
            external_reference: accountRef,
            callback_url: callbackUrl
        };

        await axios.post('https://backend.payhero.co.ke/api/v2/payments', payload, {
            headers: {
                Authorization: `Basic ${authToken}`,
                'Content-Type': 'application/json'
            }
        });
        console.log(`📡 Pay Hero callback_url used: ${callbackUrl}`);
        console.log(`📲 Pay Hero STK Push sent to ${phone}`);
        return true;
    } catch (error) {
        console.error("❌ Pay Hero STK Push Error:", error.response ? error.response.data : error.message);
        return false;
    }
};

const parseRouteName = (routeName) => {
    const parts = routeName.split(' - ').map(part => part.trim()).filter(Boolean);
    return {
        name: routeName.trim(),
        origin: parts[0] || routeName.trim(),
        destination: parts.slice(1).join(' - ') || parts[0] || routeName.trim()
    };
};

const toNumber = (value, fallback = 0) => {
    const numeric = parseFloat(value);
    return Number.isFinite(numeric) ? numeric : fallback;
};

const buildRevenueSummary = (transactions) => {
    return transactions.reduce((summary, transaction) => {
        const amount = Math.abs(toNumber(transaction.amount));
        summary.total += amount;
        summary.count += 1;
        return summary;
    }, { total: 0, count: 0 });
};

const parseWebhookBody = (req) => {
    if (req.body && Object.keys(req.body).length > 0) return req.body;
    if (!req.rawBody) return {};

    try {
        return JSON.parse(req.rawBody);
    } catch {
        try {
            return Object.fromEntries(new URLSearchParams(req.rawBody));
        } catch {
            return {};
        }
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

        const matatu = await Matatu.findOne({ where: { plateNumber } });
        if (!matatu) {
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "ERROR", msg: "Unknown Matatu" }));
            return;
        }

        const tag = await Tag.findOne({ where: { tagUid: data.tagUid }, include: User });

        if (!tag || !tag.User) {
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ status: "ERROR", msg: "Unknown Card" }));
            return;
        }

        const user = tag.User;
        const recipientConfig = await MatatuAdminRecipient.findOne({ where: { MatatuId: matatu.id } });
        const adminRecipient = recipientConfig
            ? await User.findOne({ where: { phone: recipientConfig.adminPhone, role: 'ADMIN' } })
            : null;

        if (!adminRecipient) {
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({
                status: "ERROR",
                msg: "No admin recipient configured"
            }));
            return;
        }

        // Check Balance
        if (user.balance < data.amount) {
            console.log(`⚠️ Low Balance. Triggering STK...`);
            const sent = await triggerStkPush(user.phone, data.amount, plateNumber);
            
            mqttClient.publish(`matatu/${plateNumber}/alert`, JSON.stringify({ 
                status: sent ? "INFO" : "FAIL", 
                msg: sent ? "Check Phone PIN" : "Pay Hero Error", 
                bal: user.balance 
            }));
            return;
        }

        // Process Payment
        await sequelize.transaction(async (t) => {
            await user.decrement('balance', { by: data.amount, transaction: t });
            await adminRecipient.increment('balance', { by: data.amount, transaction: t });

            await Transaction.create({
                UserId: user.id,
                MatatuId: matatu.id,
                type: 'FARE_PAYMENT',
                amount: -data.amount,
                reference: plateNumber,
                description: `Fare for ${plateNumber}`
            }, { transaction: t });

            await Transaction.create({
                UserId: adminRecipient.id,
                MatatuId: matatu.id,
                type: 'TRANSFER',
                amount: data.amount,
                reference: plateNumber,
                description: `Fare received from ${user.name || user.phone}`
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

const requireRole = (...roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({ error: "Forbidden" });
    }
    next();
};

const requireAdmin = [authenticate, requireRole('ADMIN')];

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

// 3b. Get ride history
app.get('/app/rides', authenticate, async (req, res) => {
    try {
        const rides = await Transaction.findAll({
            where: {
                UserId: req.user.id,
                type: 'FARE_PAYMENT'
            },
            include: [
                {
                    model: Matatu,
                    attributes: ['id', 'plateNumber', 'sacco', 'route', 'status'],
                    include: [
                        {
                            model: Route,
                            attributes: ['id', 'name', 'origin', 'destination', 'baseFare', 'status']
                        },
                        {
                            model: Driver,
                            attributes: ['id', 'name', 'phone', 'status']
                        }
                    ]
                }
            ],
            order: [['createdAt', 'DESC']]
        });

        const data = rides.map(ride => {
            const json = ride.toJSON();
            return {
                id: json.id,
                amount: Math.abs(toNumber(json.amount)),
                reference: json.reference,
                description: json.description,
                date: json.createdAt,
                matatu: json.Matatu ? {
                    id: json.Matatu.id,
                    plateNumber: json.Matatu.plateNumber,
                    sacco: json.Matatu.sacco,
                    route: json.Matatu.Route ? {
                        id: json.Matatu.Route.id,
                        name: json.Matatu.Route.name,
                        origin: json.Matatu.Route.origin,
                        destination: json.Matatu.Route.destination,
                        fare: json.Matatu.Route.baseFare,
                        status: json.Matatu.Route.status
                    } : null,
                    driver: json.Matatu.Driver ? {
                        id: json.Matatu.Driver.id,
                        name: json.Matatu.Driver.name,
                        phone: json.Matatu.Driver.phone,
                        status: json.Matatu.Driver.status
                    } : null
                } : null
            };
        });

        res.json({ count: data.length, rides: data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
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

// 5. Commuter fare payment by plate number
app.post('/app/payments/fare', authenticate, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const { plateNumber, amount } = req.body;
        if (!plateNumber) {
            throw new Error("plateNumber is required");
        }

        const matatu = await Matatu.findOne({
            where: { plateNumber: plateNumber.trim() },
            include: [{ model: Route }]
        });

        if (!matatu) {
            throw new Error("Matatu not found");
        }

        const recipientConfig = await MatatuAdminRecipient.findOne({ where: { MatatuId: matatu.id } });
        if (!recipientConfig) {
            throw new Error("No admin recipient configured for this matatu");
        }

        const adminRecipient = await User.findOne({ where: { phone: recipientConfig.adminPhone, role: 'ADMIN' } });
        if (!adminRecipient) {
            throw new Error("Configured admin recipient account not found");
        }

        const payer = await User.findByPk(req.user.id);
        if (!payer) {
            throw new Error("User not found");
        }

        const routeFare = matatu.Route ? toNumber(matatu.Route.baseFare, 0) : 0;
        const fareToPay = amount != null ? toNumber(amount, NaN) : routeFare;
        if (!Number.isFinite(fareToPay) || fareToPay <= 0) {
            throw new Error("A valid fare amount is required");
        }

        if (payer.balance < fareToPay) {
            await t.rollback();
            const sent = await triggerStkPush(payer.phone, fareToPay, matatu.plateNumber);
            return res.status(400).json({
                error: "Insufficient balance",
                message: sent ? "Top-up prompt sent to your phone" : "Top-up could not be initiated",
                balance: payer.balance,
                requiredAmount: fareToPay
            });
        }

        await payer.decrement('balance', { by: fareToPay, transaction: t });
        await adminRecipient.increment('balance', { by: fareToPay, transaction: t });

        await Transaction.create({
            UserId: payer.id,
            MatatuId: matatu.id,
            type: 'FARE_PAYMENT',
            amount: -fareToPay,
            reference: matatu.plateNumber,
            description: `Fare for ${matatu.plateNumber}`
        }, { transaction: t });

        await Transaction.create({
            UserId: adminRecipient.id,
            MatatuId: matatu.id,
            type: 'TRANSFER',
            amount: fareToPay,
            reference: matatu.plateNumber,
            description: `Fare received from ${payer.name || payer.phone}`
        }, { transaction: t });

        await t.commit();

        const updatedPayer = await User.findByPk(payer.id);
        const updatedAdmin = await User.findByPk(adminRecipient.id);

        res.json({
            message: "Fare payment successful",
            plateNumber: matatu.plateNumber,
            route: matatu.route,
            amount: fareToPay,
            recipient: {
                adminPhone: adminRecipient.phone,
                adminName: adminRecipient.name
            },
            balances: {
                payer: updatedPayer ? updatedPayer.balance : null,
                recipient: updatedAdmin ? updatedAdmin.balance : null
            }
        });
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
            include: [
                { model: Review, attributes: ['rating'] },
                { model: Route },
                { model: Driver }
            ]
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

// 6. User app matatu catalog
app.get('/app/matatus', authenticate, async (req, res) => {
    try {
        const matatus = await Matatu.findAll({
            include: [
                { model: Review, attributes: ['rating'] },
                { model: Route, attributes: ['id', 'name', 'origin', 'destination', 'baseFare', 'status'] },
                { model: Driver, attributes: ['id', 'name', 'phone', 'status'] }
            ],
            order: [['createdAt', 'DESC']]
        });

        const data = matatus.map(matatu => {
            const json = matatu.toJSON();
            const total = json.Reviews.reduce((sum, review) => sum + review.rating, 0);
            const count = json.Reviews.length;

            return {
                id: json.id,
                plateNumber: json.plateNumber,
                sacco: json.sacco,
                status: json.status,
                route: json.Route ? {
                    id: json.Route.id,
                    name: json.Route.name,
                    origin: json.Route.origin,
                    destination: json.Route.destination,
                    fare: json.Route.baseFare,
                    status: json.Route.status
                } : null,
                driver: json.Driver ? {
                    id: json.Driver.id,
                    name: json.Driver.name,
                    phone: json.Driver.phone,
                    status: json.Driver.status
                } : null,
                averageRating: count > 0 ? Number((total / count).toFixed(1)) : null,
                reviewCount: count
            };
        });

        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 7. User app drivers catalog
app.get('/app/drivers', authenticate, async (req, res) => {
    try {
        const drivers = await Driver.findAll({
            include: [{ model: Matatu, attributes: ['id', 'plateNumber', 'status', 'RouteId'] }],
            order: [['createdAt', 'DESC']]
        });

        const data = drivers.map(driver => {
            const json = driver.toJSON();
            return {
                id: json.id,
                name: json.name,
                phone: json.phone,
                status: json.status,
                assignedMatatus: json.Matatus
            };
        });

        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 8. User app route catalog with fare
app.get('/app/routes', authenticate, async (req, res) => {
    try {
        const routes = await Route.findAll({
            include: [{ model: Matatu, attributes: ['id', 'plateNumber', 'status'] }],
            order: [['createdAt', 'DESC']]
        });

        const data = routes.map(route => {
            const json = route.toJSON();
            return {
                id: json.id,
                name: json.name,
                origin: json.origin,
                destination: json.destination,
                fare: json.baseFare,
                status: json.status,
                matatus: json.Matatus
            };
        });

        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 9. User app matatu ratings
app.get('/app/matatus/:id/ratings', authenticate, async (req, res) => {
    try {
        const matatu = await Matatu.findByPk(req.params.id);
        if (!matatu) {
            return res.status(404).json({ error: 'Matatu not found' });
        }

        const reviews = await Review.findAll({
            where: { MatatuId: matatu.id },
            include: [{ model: User, attributes: ['id', 'name'] }],
            order: [['createdAt', 'DESC']]
        });

        const summary = buildRevenueSummary(reviews.map(review => ({ amount: review.rating })));

        res.json({
            matatu: { id: matatu.id, plateNumber: matatu.plateNumber },
            averageRating: summary.count > 0 ? Number((summary.total / summary.count).toFixed(1)) : null,
            reviewCount: summary.count,
            ratings: reviews
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 10. Admin dashboard
app.get('/admin/dashboard', requireAdmin, async (req, res) => {
    try {
        const [matatus, routes, drivers, payoutSchedules] = await Promise.all([
            Matatu.findAll({
                include: [
                    { model: Review, attributes: ['rating'] },
                    { model: Transaction, attributes: ['amount', 'type', 'reference'] },
                    { model: Route },
                    { model: Driver }
                ]
            }),
            Route.count(),
            Driver.count(),
            PayoutSchedule.findAll({ include: [Driver, Matatu, Route] })
        ]);

        const driverRevenue = new Map();
        const matatuRevenue = [];
        let totalRevenue = 0;
        let totalRatings = 0;
        let ratingCount = 0;

        for (const matatu of matatus) {
            const json = matatu.toJSON();
            const revenue = json.Transactions
                .filter(transaction => transaction.type === 'FARE_PAYMENT')
                .reduce((sum, transaction) => sum + Math.abs(toNumber(transaction.amount)), 0);
            const reviews = json.Reviews || [];
            const reviewTotal = reviews.reduce((sum, review) => sum + review.rating, 0);
            const matatuRatingCount = reviews.length;
            const averageRating = matatuRatingCount > 0 ? reviewTotal / matatuRatingCount : null;
            totalRevenue += revenue;
            totalRatings += reviewTotal;
            ratingCount += matatuRatingCount;

            if (json.DriverId) {
                const currentRevenue = driverRevenue.get(json.DriverId) || 0;
                driverRevenue.set(json.DriverId, currentRevenue + revenue);
            }

            matatuRevenue.push({
                id: json.id,
                plateNumber: json.plateNumber,
                route: json.route,
                routeDetails: json.Route || null,
                driver: json.Driver || null,
                revenue,
                averageRating: averageRating !== null ? Number(averageRating.toFixed(1)) : null,
                reviewCount: matatuRatingCount
            });
        }

        const driversWithRevenue = Array.from(driverRevenue.entries()).map(([driverId, revenue]) => ({
            driverId,
            revenue
        }));

        const payoutSummary = payoutSchedules.map(schedule => {
            const matatuRevenueMatch = schedule.MatatuId
                ? matatuRevenue.find(item => item.id === schedule.MatatuId)?.revenue || 0
                : matatuRevenue
                    .filter(item => !schedule.DriverId || item.driver?.id === schedule.DriverId)
                    .reduce((sum, item) => sum + item.revenue, 0);

            const payoutAmount = schedule.fixedAmount != null
                ? toNumber(schedule.fixedAmount)
                : matatuRevenueMatch * toNumber(schedule.payoutPercentage);

            return {
                id: schedule.id,
                frequency: schedule.frequency,
                status: schedule.status,
                nextPayoutAt: schedule.nextPayoutAt,
                lastPayoutAt: schedule.lastPayoutAt,
                driver: schedule.Driver || null,
                matatu: schedule.Matatu || null,
                route: schedule.Route || null,
                payoutAmount
            };
        });

        res.json({
            summary: {
                routes,
                drivers,
                matatus: matatus.length,
                totalRevenue,
                averageRating: ratingCount > 0 ? Number((totalRatings / ratingCount).toFixed(1)) : null,
                payoutSchedules: payoutSchedules.length
            },
            matatus: matatuRevenue,
            driverRevenue: driversWithRevenue,
            payoutSchedules: payoutSummary
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 7. Admin route enrollment
app.post('/admin/routes', requireAdmin, async (req, res) => {
    try {
        const { name, origin, destination, baseFare } = req.body;
        if (!name || !origin || !destination) {
            return res.status(400).json({ error: "name, origin and destination are required" });
        }

        const route = await Route.create({
            name: name.trim(),
            origin: origin.trim(),
            destination: destination.trim(),
            baseFare: toNumber(baseFare)
        });

        res.status(201).json(route);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 8. Admin set route fare
app.patch('/admin/routes/:id/fare', requireAdmin, async (req, res) => {
    try {
        const route = await Route.findByPk(req.params.id);
        if (!route) {
            return res.status(404).json({ error: "Route not found" });
        }

        const fare = toNumber(req.body.baseFare, NaN);
        if (!Number.isFinite(fare) || fare < 0) {
            return res.status(400).json({ error: "baseFare must be a non-negative number" });
        }

        await route.update({ baseFare: fare });
        res.json({ message: "Route fare updated", route });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 9. Admin delete route
app.delete('/admin/routes/:id', requireAdmin, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const route = await Route.findByPk(req.params.id, { transaction: t });
        if (!route) {
            await t.rollback();
            return res.status(404).json({ error: "Route not found" });
        }

        const [matatuCount, payoutCount] = await Promise.all([
            Matatu.count({ where: { RouteId: route.id }, transaction: t }),
            PayoutSchedule.count({ where: { RouteId: route.id }, transaction: t })
        ]);

        if (matatuCount > 0 || payoutCount > 0) {
            await t.rollback();
            return res.status(409).json({
                error: "Route has dependent records",
                details: {
                    matatus: matatuCount,
                    payoutSchedules: payoutCount
                }
            });
        }

        await route.destroy({ transaction: t });
        await t.commit();
        res.json({ message: "Route deleted successfully", routeId: Number(req.params.id) });
    } catch (e) {
        await t.rollback();
        res.status(500).json({ error: e.message });
    }
});

// 10. Admin driver enrollment
app.post('/admin/drivers', requireAdmin, async (req, res) => {
    try {
        const { name, phone, licenseNumber } = req.body;
        if (!name) {
            return res.status(400).json({ error: "Driver name is required" });
        }

        const driver = await Driver.create({
            name: name.trim(),
            phone: phone ? formatPhone(phone) : null,
            licenseNumber: licenseNumber ? licenseNumber.trim() : null
        });

        res.status(201).json(driver);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 11. Admin delete driver
app.delete('/admin/drivers/:id', requireAdmin, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const driver = await Driver.findByPk(req.params.id, { transaction: t });
        if (!driver) {
            await t.rollback();
            return res.status(404).json({ error: "Driver not found" });
        }

        const [matatuCount, payoutCount] = await Promise.all([
            Matatu.count({ where: { DriverId: driver.id }, transaction: t }),
            PayoutSchedule.count({ where: { DriverId: driver.id }, transaction: t })
        ]);

        if (matatuCount > 0 || payoutCount > 0) {
            await t.rollback();
            return res.status(409).json({
                error: "Driver has dependent records",
                details: {
                    matatus: matatuCount,
                    payoutSchedules: payoutCount
                }
            });
        }

        await driver.destroy({ transaction: t });
        await t.commit();
        res.json({ message: "Driver deleted successfully", driverId: Number(req.params.id) });
    } catch (e) {
        await t.rollback();
        res.status(500).json({ error: e.message });
    }
});

// 12. Admin matatu enrollment
app.post('/admin/matatus', requireAdmin, async (req, res) => {
    try {
        const { plateNumber, routeId, routeName, origin, destination, sacco, driverId, driverName, driverPhone, licenseNumber, adminPhone } = req.body;
        if (!plateNumber) {
            return res.status(400).json({ error: "plateNumber is required" });
        }

        const recipientPhone = formatPhone(adminPhone || req.user.phone);
        const adminUser = await User.findOne({ where: { phone: recipientPhone, role: 'ADMIN' } });
        if (!adminUser) {
            return res.status(404).json({ error: 'Admin recipient account not found' });
        }

        let routeRecord = null;
        if (routeId) {
            routeRecord = await Route.findByPk(routeId);
            if (!routeRecord) return res.status(404).json({ error: "Route not found" });
        } else if (routeName) {
            const parsedRoute = parseRouteName(routeName);
            [routeRecord] = await Route.findOrCreate({
                where: { name: parsedRoute.name },
                defaults: {
                    name: parsedRoute.name,
                    origin: origin ? origin.trim() : parsedRoute.origin,
                    destination: destination ? destination.trim() : parsedRoute.destination
                }
            });
        }

        let driverRecord = null;
        if (driverId) {
            driverRecord = await Driver.findByPk(driverId);
            if (!driverRecord) return res.status(404).json({ error: "Driver not found" });
        } else if (driverName) {
            [driverRecord] = await Driver.findOrCreate({
                where: { name: driverName.trim() },
                defaults: {
                    name: driverName.trim(),
                    phone: driverPhone ? formatPhone(driverPhone) : null,
                    licenseNumber: licenseNumber ? licenseNumber.trim() : null
                }
            });
        }

        const [matatu, created] = await Matatu.findOrCreate({
            where: { plateNumber: plateNumber.trim() },
            defaults: {
                plateNumber: plateNumber.trim(),
                route: routeRecord ? routeRecord.name : null,
                sacco: sacco ? sacco.trim() : null,
                RouteId: routeRecord ? routeRecord.id : null,
                DriverId: driverRecord ? driverRecord.id : null
            }
        });

        if (!created) {
            await matatu.update({
                route: routeRecord ? routeRecord.name : matatu.route,
                sacco: sacco ? sacco.trim() : matatu.sacco,
                RouteId: routeRecord ? routeRecord.id : matatu.RouteId,
                DriverId: driverRecord ? driverRecord.id : matatu.DriverId
            });
        }

        await MatatuAdminRecipient.upsert({
            MatatuId: matatu.id,
            adminPhone: adminUser.phone
        });

        const refreshed = await Matatu.findByPk(matatu.id, {
            include: [Route, Driver, { model: MatatuAdminRecipient, as: 'RecipientConfig' }]
        });
        res.status(created ? 201 : 200).json(refreshed);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 13. Admin change matatu route association
app.patch('/admin/matatus/:id/route', requireAdmin, async (req, res) => {
    try {
        const matatu = await Matatu.findByPk(req.params.id);
        if (!matatu) {
            return res.status(404).json({ error: "Matatu not found" });
        }

        const { routeId, routeName, origin, destination } = req.body;
        if (!routeId && !routeName) {
            return res.status(400).json({ error: "routeId or routeName is required" });
        }

        let routeRecord = null;
        if (routeId) {
            routeRecord = await Route.findByPk(routeId);
            if (!routeRecord) return res.status(404).json({ error: "Route not found" });
        } else {
            const parsedRoute = parseRouteName(routeName);
            [routeRecord] = await Route.findOrCreate({
                where: { name: parsedRoute.name },
                defaults: {
                    name: parsedRoute.name,
                    origin: origin ? origin.trim() : parsedRoute.origin,
                    destination: destination ? destination.trim() : parsedRoute.destination
                }
            });
        }

        await matatu.update({
            RouteId: routeRecord.id,
            route: routeRecord.name
        });

        const refreshed = await Matatu.findByPk(matatu.id, { include: [Route, Driver] });
        res.json({ message: "Matatu route updated", matatu: refreshed });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 14. Admin change matatu recipient account
app.patch('/admin/matatus/:id/recipient', requireAdmin, async (req, res) => {
    try {
        const matatu = await Matatu.findByPk(req.params.id);
        if (!matatu) {
            return res.status(404).json({ error: "Matatu not found" });
        }

        const recipientPhone = formatPhone(req.body.adminPhone || req.user.phone);
        const adminUser = await User.findOne({ where: { phone: recipientPhone, role: 'ADMIN' } });
        if (!adminUser) {
            return res.status(404).json({ error: 'Admin recipient account not found' });
        }

        await MatatuAdminRecipient.upsert({
            MatatuId: matatu.id,
            adminPhone: adminUser.phone
        });

        const refreshed = await Matatu.findByPk(matatu.id, {
            include: [Route, Driver, { model: MatatuAdminRecipient, as: 'RecipientConfig' }]
        });

        res.json({ message: 'Matatu recipient updated', matatu: refreshed });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// 15. Admin delete matatu
app.delete('/admin/matatus/:id', requireAdmin, async (req, res) => {
    const t = await sequelize.transaction();
    try {
        const matatu = await Matatu.findByPk(req.params.id, { transaction: t });
        if (!matatu) {
            await t.rollback();
            return res.status(404).json({ error: "Matatu not found" });
        }

        await Review.destroy({ where: { MatatuId: matatu.id }, transaction: t });
        await Transaction.destroy({ where: { MatatuId: matatu.id }, transaction: t });
        await PayoutSchedule.destroy({ where: { MatatuId: matatu.id }, transaction: t });
        await MatatuAdminRecipient.destroy({ where: { MatatuId: matatu.id }, transaction: t });
        await matatu.destroy({ transaction: t });

        await t.commit();
        res.json({ message: "Matatu deleted successfully", matatuId: Number(req.params.id) });
    } catch (e) {
        await t.rollback();
        res.status(500).json({ error: e.message });
    }
});

// 16. Admin payout schedule management
app.post('/admin/payout-schedules', requireAdmin, async (req, res) => {
    try {
        const { driverId, matatuId, routeId, frequency, payoutPercentage, fixedAmount, nextPayoutAt, notes } = req.body;

        if (!driverId) {
            return res.status(400).json({ error: "driverId is required" });
        }

        const driver = await Driver.findByPk(driverId);
        if (!driver) return res.status(404).json({ error: "Driver not found" });

        if (matatuId) {
            const matatu = await Matatu.findByPk(matatuId);
            if (!matatu) return res.status(404).json({ error: "Matatu not found" });
        }

        if (routeId) {
            const route = await Route.findByPk(routeId);
            if (!route) return res.status(404).json({ error: "Route not found" });
        }

        const schedule = await PayoutSchedule.create({
            DriverId: driverId,
            MatatuId: matatuId || null,
            RouteId: routeId || null,
            frequency: frequency || 'WEEKLY',
            payoutPercentage: payoutPercentage != null ? toNumber(payoutPercentage, 0.8) : 0.8,
            fixedAmount: fixedAmount != null ? toNumber(fixedAmount) : null,
            nextPayoutAt: nextPayoutAt ? new Date(nextPayoutAt) : new Date(),
            notes: notes || null
        });

        const populated = await PayoutSchedule.findByPk(schedule.id, { include: [Driver, Matatu, Route] });
        res.status(201).json(populated);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.get('/admin/payout-schedules', requireAdmin, async (req, res) => {
    try {
        const schedules = await PayoutSchedule.findAll({ include: [Driver, Matatu, Route], order: [['createdAt', 'DESC']] });
        res.json(schedules);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/admin/routes', requireAdmin, async (req, res) => {
    try {
        const routes = await Route.findAll({ order: [['createdAt', 'DESC']] });
        res.json(routes);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/admin/drivers', requireAdmin, async (req, res) => {
    try {
        const drivers = await Driver.findAll({
            include: [
                { model: Matatu, include: [Review, Route, Transaction] },
                { model: PayoutSchedule, include: [Matatu, Route] }
            ],
            order: [['createdAt', 'DESC']]
        });

        const data = drivers.map(driver => {
            const json = driver.toJSON();
            const matatuRevenue = json.Matatus.reduce((sum, matatu) => {
                const revenue = (matatu.Transactions || [])
                    .filter(transaction => transaction.type === 'FARE_PAYMENT')
                    .reduce((total, transaction) => total + Math.abs(toNumber(transaction.amount)), 0);
                return sum + revenue;
            }, 0);

            const reviewTotals = json.Matatus.reduce((acc, matatu) => {
                const ratings = matatu.Reviews || [];
                acc.count += ratings.length;
                acc.total += ratings.reduce((sum, review) => sum + review.rating, 0);
                return acc;
            }, { count: 0, total: 0 });

            return {
                ...json,
                revenue: matatuRevenue,
                averageRating: reviewTotals.count > 0 ? Number((reviewTotals.total / reviewTotals.count).toFixed(1)) : null
            };
        });

        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/admin/matatus', requireAdmin, async (req, res) => {
    try {
        const matatus = await Matatu.findAll({
            include: [
                { model: Review, attributes: ['rating', 'comment'] },
                { model: Transaction, attributes: ['amount', 'type'] },
                { model: Route },
                { model: Driver }
            ],
            order: [['createdAt', 'DESC']]
        });

        const data = matatus.map(matatu => {
            const json = matatu.toJSON();
            const revenue = json.Transactions
                .filter(transaction => transaction.type === 'FARE_PAYMENT')
                .reduce((sum, transaction) => sum + Math.abs(toNumber(transaction.amount)), 0);
            const total = json.Reviews.reduce((sum, review) => sum + review.rating, 0);
            const count = json.Reviews.length;

            return {
                ...json,
                revenue,
                averageRating: count > 0 ? Number((total / count).toFixed(1)) : null,
                reviewCount: count
            };
        });

        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
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
        console.log(`✅ Tag ${req.body.tagUid} enrolled for user ${req.user.id}`);
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

// Admin registration
app.post('/auth/admin/register', async (req, res) => {
    console.log("Admin Registration Attempt:", { body: req.body });
    try {
        const { name, phone, pin } = req.body;
        if (!name || !phone || !pin) {
            return res.status(400).json({ error: "name, phone and pin are required" });
        }

        const pinHash = await bcrypt.hash(pin, 10);
        const admin = await User.create({
            name,
            phone: formatPhone(phone),
            pinHash,
            role: 'ADMIN'
        });

        res.status(201).json({ userId: admin.id, role: admin.role });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Login
app.post('/auth/login', async (req, res) => {
    try {
        const { phone, pin } = req.body;
        const user = await User.findOne({ where: { phone: formatPhone(phone) } });
        if (!user || !(await bcrypt.compare(pin, user.pinHash))) {
            return res.status(401).json({ error: "Invalid Phone or PIN" });
        }
        const token = jwt.sign({ id: user.id, phone: user.phone, role: user.role }, SECRET_KEY, { expiresIn: '30d' });
        res.json({ message: "Login successful", token, user: { id: user.id, name: user.name, balance: user.balance, role: user.role } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin login
app.post('/auth/admin/login', async (req, res) => {
    try {
        const { phone, pin } = req.body;
        const user = await User.findOne({ where: { phone: formatPhone(phone), role: 'ADMIN' } });

        if (!user || !(await bcrypt.compare(pin, user.pinHash))) {
            return res.status(401).json({ error: "Invalid Admin Credentials" });
        }

        const token = jwt.sign({ id: user.id, phone: user.phone, role: user.role }, SECRET_KEY, { expiresIn: '30d' });
        res.json({
            message: "Admin login successful",
            token,
            user: { id: user.id, name: user.name, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/hooks/payhero', (req, res) => {
    res.status(200).json({ ok: true, route: '/hooks/payhero', method: 'GET' });
});

// --- PAY HERO CALLBACK ---
app.post('/hooks/payhero', async (req, res) => {
    const incomingBody = parseWebhookBody(req);
    console.log("📥 Pay Hero Callback Received", {
        method: req.method,
        contentType: req.headers['content-type'],
        userAgent: req.headers['user-agent'],
        bodyPreview: JSON.stringify(incomingBody).slice(0, 300)
    });

    try {
        const data = incomingBody && incomingBody.response ? incomingBody.response : incomingBody;
        const resultCode = Number(data?.ResultCode);

        if (!data || Number.isNaN(resultCode) || resultCode !== 0) {
            const errorMessage = data?.ResultDesc || data?.result_desc || 'Missing or invalid callback payload';
            console.log("❌ Pay Hero Transaction Failed:", errorMessage);
            return res.status(400).json({ success: false, error: errorMessage });
        }

        const amount = Number(data.Amount || data.amount || 0);
        const rawPhone = (data.Phone || data.phone_number || data.phone || '').toString();
        const receipt = data.MpesaReceiptNumber || data.mpesa_receipt_number || data.transaction_reference || 'NO_RECEIPT';
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
                description: "Pay Hero Deposit" 
            });
            
            await user.reload(); 
            console.log(`✅ Wallet Updated! New Balance: ${user.balance}`);
        } else {
            console.error(`⚠️ User Not Found! Phone in DB does not match ${phone}`);
            return res.status(400).json({ success: false, error: "User not found for this phone number" });
            
        }
        
        res.json({ success: true });
    } catch (err) { 
        console.error("Callback Error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') {
        console.error('❌ JSON Parse Error', {
            path: req.originalUrl,
            contentType: req.headers['content-type'],
            bodyPreview: (err.body || '').toString().slice(0, 300)
        });
        return res.status(400).json({ success: false, error: 'Invalid JSON payload' });
    }

    return next(err);
});

app.listen(3000, () => console.log("🚀 Server Running"));