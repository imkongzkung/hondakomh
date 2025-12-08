// ==========================================
// 1. Imports & Configuration
// ==========================================
const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); 
const nodemailer = require('nodemailer');
const axios = require('axios');
const cheerio = require('cheerio');
const app = express();
const PORT= process.env.PORT || 3000;
app.set('trust proxy', true);

// กำหนด Secret Key ให้เหมือนกันทั้งระบบ (สำคัญมาก!)
const SECRET_KEY = '112288'; 

// ==========================================
// 2. Middleware Setup
// ==========================================

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'กรุณาเข้าสู่ระบบ (ไม่พบ Token)' });
    }

    // แก้ไข: ใช้ตัวแปร SECRET_KEY เพื่อความชัวร์
    jwt.verify(token, SECRET_KEY, (err, decodedUser) => {
        if (err) {
            return res.status(403).json({ message: 'Token ไม่ถูกต้อง หรือหมดอายุแล้ว' });
        }
        req.user = decodedUser;
        next();
    });
};

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// ==========================================
// 3. Database Connection
// ==========================================
// แนะนำให้ใช้ createPool เพื่อป้องกัน Connection หลุด
// แก้ไขการเชื่อมต่อ Database
const db = mysql.createPool({
    host: process.env.DB_HOST || 'bkksqrrfa1pneuqlzcyc-mysql.services.clever-cloud.com',      // ถ้ามีค่าใน Cloud ให้ใช้ Cloud ถ้าไม่มีให้ใช้ localhost
    user: process.env.DB_USER || 'ugdkxrqhm2hyhcmh',
    password: process.env.DB_PASSWORD || '7bf1wZMIub8rUJcyKB3Z',
    database: process.env.DB_NAME || 'bkksqrrfa1pneuqlzcyc',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ==========================================
// 4. API Routes (Auth & User)
// ==========================================

// [POST] สมัครสมาชิก
app.post('/api/register', (req, res) => {
    const { username, password, fullname, phone } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const sql = 'INSERT INTO users (username, password, fullname, phone) VALUES (?, ?, ?, ?)';
    db.query(sql, [username, hashedPassword, fullname, phone], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Username นี้ถูกใช้ไปแล้ว หรือระบบขัดข้อง' });
        }
        res.json({ success: true, message: 'สมัครสมาชิกสำเร็จ' });
    });
});

// [POST] เข้าสู่ระบบ (แก้ไขให้เช็ค Database จริง)
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // 1. หา User ใน Database
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // 2. ถ้าไม่เจอ User
        if (results.length === 0) {
            return res.status(401).json({ message: 'Username หรือ Password ไม่ถูกต้อง' });
        }

        const user = results[0];

        // 3. เช็ค Password ด้วย bcrypt
        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Username หรือ Password ไม่ถูกต้อง' });
        }

        // 4. สร้าง Token (ใช้ SECRET_KEY ตัวเดียวกับ Middleware)
        const token = jwt.sign(
            { id: user.id, username: user.username, fullname: user.fullname }, 
            SECRET_KEY, 
            { expiresIn: '1h' }
        );

        // ส่ง Token และข้อมูล User กลับไป
        res.json({ 
            message: 'Login สำเร็จ', 
            token: token, 
            user: { id: user.id, fullname: user.fullname, phone: user.phone } 
        });
    });
});

// [GET] ดูประวัติการจองของฉัน (แก้ไขชื่อ middleware และการดึง ID)
// เปลี่ยน verifyLogin -> authMiddleware
app.get('/api/my-bookings', authMiddleware, (req, res) => {
    
    // ดึง ID จาก Token โดยตรง (ปลอดภัยกว่ารับจาก URL)
    const userId = req.user.id;
    
    const sql = 'SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC';
    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// ==========================================
// 5. API Routes (General Cars)
// ==========================================

app.get('/api/banners', (req, res) => {
    const sql = 'SELECT * FROM banners';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.get('/api/cars', async (req, res) => {
    try {
        const [cars] = await db.promise().query('SELECT * FROM cars');
        const [colors] = await db.promise().query('SELECT * FROM car_colors');
        const carsWithColors = cars.map(car => ({
            ...car,
            colors: colors.filter(c => c.car_id === car.id)
        }));
        res.json(carsWithColors);
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/cars/compare', async (req, res) => {
    const ids = req.query.ids; 
    if (!ids) return res.status(400).json({ error: 'No IDs provided' });
    const idArray = ids.split(',').map(id => parseInt(id)).filter(id => !isNaN(id));
    if (idArray.length === 0) return res.json([]);

    try {
        const query = `SELECT * FROM cars WHERE id IN (${idArray.join(',')})`;
        const [cars] = await db.promise().query(query);
        res.json(cars);
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/cars/:id', async (req, res) => {
    const carId = req.params.id;
    try {
        const [cars] = await db.promise().query('SELECT * FROM cars WHERE id = ?', [carId]);
        if (cars.length === 0) return res.status(404).json({ error: 'Car not found' });
        const [colors] = await db.promise().query('SELECT * FROM car_colors WHERE car_id = ?', [carId]);
        res.json({ ...cars[0], colors: colors });
    } catch (err) { res.status(500).send(err); }
});

app.get('/api/branches', (req, res) => {
    db.query('SELECT * FROM branches', (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// ==========================================
// 6. API Routes (Actions)
// ==========================================

app.post('/api/test-drive', authMiddleware, (req, res) => {
    // ดึง User ID จาก Token ที่ Login มา
    const user_id = req.user.id; 
    
    const { customer_name, phone, car_model, branch_name, appointment_date, appointment_time } = req.body;
    
    const sql = 'INSERT INTO orders (customer_name, phone, car_model, branch_name, appointment_date, appointment_time, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)';
    
    db.query(sql, [customer_name, phone, car_model, branch_name, appointment_date, appointment_time, user_id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send(err);
        }
        res.json({ message: 'Booking Success', id: result.insertId });
    });
});

// [POST] รับข้อความจากหน้าติดต่อเรา (เก็บลง Database อย่างเดียว)
app.post('/api/contact', (req, res) => {
    const { name, phone, topic, message } = req.body;
    
    // แสดง Log ดูหน่อยว่าข้อมูลมาถึงไหม
    console.log("📩 ได้รับข้อความใหม่:", { name, phone, topic });

    const sql = 'INSERT INTO contact_messages (name, phone, topic, message) VALUES (?, ?, ?, ?)';
    
    db.query(sql, [name, phone, topic, message], (err, result) => {
        if (err) {
            console.error("❌ Database Error:", err);
            return res.status(500).json({ success: false, error: 'บันทึกข้อมูลไม่สำเร็จ' });
        }
        
        console.log("✅ บันทึกเรียบร้อย! ID:", result.insertId);
        
        // ส่งข้อความตอบกลับไปหาหน้าเว็บทันที
        res.json({ success: true, message: 'บันทึกข้อมูลสำเร็จ' });
    });
});

// [GET] ดึงข่าวจาก Honda (Web Scraping - อัปเดตตามรูปภาพ)
app.get('/api/honda-news', async (req, res) => {
    try {
        const targetUrl = 'https://www.honda.co.th/news'; 
        
        // เพิ่ม headers เพื่อให้เหมือน Browser ทั่วไป (ป้องกันการโดนบล็อก)
        const { data } = await axios.get(targetUrl, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' }
        });
        
        const $ = cheerio.load(data);
        const newsList = [];

        // 1. เปลี่ยน Selector เป็น .col-12.col-md-6 (ตามรูป)
        $('.col-12.col-md-6').each((index, element) => {
            if (newsList.length >= 6) return; // เอาแค่ 6 ข่าวแรก

            // 2. ดึงหัวข้อจาก .title-news (ตามรูป)
            const title = $(element).find('.title-news').text().trim();
            
            // *สำคัญ* เช็คก่อนว่าใช่กล่องข่าวไหม (ถ้าไม่มี title แสดงว่าเป็น div เปล่าๆ ให้ข้ามไป)
            if (!title) return;

            // 3. ดึงลิงก์จาก tag <a>
            const link = $(element).find('a').attr('href');

            // 4. ดึงรูปจาก .img-news (ตามรูป)
            let image = $(element).find('.img-news').attr('src');

            // แก้ลิงค์รูปภาพ (ถ้ามาไม่เต็ม)
            if (image && !image.startsWith('http')) {
                image = 'https://www.honda.co.th' + image;
            }

            if (title && link) {
                newsList.push({
                    title: title,
                    link: link,
                    image: image || 'https://placehold.co/600x400?text=No+Image'
                });
            }
        });

        res.json(newsList);

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'ดึงข่าวไม่สำเร็จ' });
    }
});

// [GET] API สำหรับนับและดึงยอดผู้เข้าชม
app.get('/api/visit-count', (req, res) => {
    // 1. หา IP Address ของผู้ใช้
    // (ถ้าอยู่บน Host จริงมักจะเป็น x-forwarded-for ถ้า localhost จะเป็น ::1)
    let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // แปลง IP ของ Localhost (::1) ให้เป็น IPv4 ธรรมดาเพื่อความสวยงาม
    if (ip === '::1') ip = '127.0.0.1';

    // 2. พยายามบันทึก IP ลง Database (ใช้ INSERT IGNORE เพื่อข้ามถ้ามี IP ซ้ำ)
    const sqlInsert = 'INSERT IGNORE INTO site_visits (ip_address) VALUES (?)';
    
    db.query(sqlInsert, [ip], (err, result) => {
        if (err) {
            console.error('Error recording visit:', err);
            // ถึง Error ตอนบันทึก ก็ยังต้องทำงานต่อเพื่อส่งยอดวิวกลับไป
        }

        // 3. ดึงยอดรวมทั้งหมด (Count) ส่งกลับไป
        const sqlCount = 'SELECT COUNT(*) as total FROM site_visits';
        db.query(sqlCount, (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            const totalVisits = results[0].total;
            res.json({ total_visits: totalVisits, your_ip: ip });
        });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});






