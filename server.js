require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json());
app.use(cors());

// --- DATABASE CONNECTION (PostgreSQL) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, 
    // e.g., postgres://username:password@localhost:5432/coffee_shop
});

const helmet = require('helmet');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      "default-src": ["'self'"], // Allow resources from your own domain
      "script-src": ["'self'", "https://cdn.tailwindcss.com", "https://cdnjs.cloudflare.com"], // Allow your UI libraries
      "img-src": ["'self'", "data:", "https://*"], // Allow images from yourself and external links
      "connect-src": ["'self'", "https://campobrew.onrender.com"] // Allow API calls to your backend
    },
  })
);




// --- MIDDLEWARE ---
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden. Admin access required.' });
        }
        req.user = decoded;
        next();
    });
};

// ==========================================
//               AUTHENTICATION
// ==========================================

// favicon.ico route to prevent unnecessary 404 errors in logs
app.get('/favicon.ico', (req, res) => res.status(204).end());



// Admin Registration (Secure this with a secret key in .env)
app.post('/api/admin/register', async (req, res) => {
    const { name, email, password, adminSecret } = req.body;

    // Check if the secret key matches what's in your .env
    if (adminSecret !== process.env.ADMIN_REGISTRATION_SECRET) {
        return res.status(403).json({ error: 'Invalid Admin Secret Key' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email',
            [name, email, hashedPassword, 'admin']
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
        res.status(500).json({ error: err.message });
    }
});

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);
        const user = result.rows[0];

        if (user && await bcrypt.compare(password, user.password_hash)) {
            const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
            res.json({ token, user: { name: user.name, email: user.email } });
        } else {
            res.status(401).json({ error: 'Invalid admin credentials' });
        }
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
//               PRODUCTS API
// ==========================================

// Public: Get all products (with optional search & category filters)
app.get('/api/products', async (req, res) => {
    const { category, search } = req.query;
    let query = 'SELECT * FROM products WHERE 1=1';
    let params = [];

    if (category) {
        params.push(category);
        query += ` AND category = $${params.length}`;
    }
    if (search) {
        params.push(`%${search}%`);
        query += ` AND name ILIKE $${params.length}`;
    }
    query += ' ORDER BY created_at DESC';

    try {
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public: Get single product by ID
app.get('/api/products/:id', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products WHERE id = $1', [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Add new product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
    const { name, description, price, category, image_url, stock } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO products (name, description, price, category, image_url, stock) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, description, price, category, image_url, stock]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Update existing product
app.put('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    const { name, description, price, category, image_url, stock } = req.body;
    try {
        const result = await pool.query(
            'UPDATE products SET name = $1, description = $2, price = $3, category = $4, image_url = $5, stock = $6 WHERE id = $7 RETURNING *',
            [name, description, price, category, image_url, stock, req.params.id]
        );
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Delete product
app.delete('/api/admin/products/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM products WHERE id = $1', [req.params.id]);
        res.json({ message: 'Product successfully deleted' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
//               BLOGS API
// ==========================================

// Public: Get all blogs
app.get('/api/blogs', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM blogs ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Add a blog post
app.post('/api/admin/blogs', verifyAdmin, async (req, res) => {
    const { title, content, author, image_url } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO blogs (title, content, author, image_url) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, content, author, image_url]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Update blog post
app.put('/api/admin/blogs/:id', verifyAdmin, async (req, res) => {
    const { title, content, author, image_url } = req.body;
    try {
        const result = await pool.query(
            'UPDATE blogs SET title = $1, content = $2, author = $3, image_url = $4 WHERE id = $5 RETURNING *',
            [title, content, author, image_url, req.params.id]
        );
        res.json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Delete blog post
app.delete('/api/admin/blogs/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM blogs WHERE id = $1', [req.params.id]);
        res.json({ message: 'Blog deleted' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
//               REVIEWS API
// ==========================================

// Public: Get approved reviews for a specific product
app.get('/api/reviews/:productId', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM reviews WHERE product_id = $1 AND approved = true ORDER BY created_at DESC', 
            [req.params.productId]
        );
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public: Submit a new review (defaults to unapproved)
app.post('/api/reviews', async (req, res) => {
    const { product_id, user_name, rating, comment } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO reviews (product_id, user_name, rating, comment) VALUES ($1, $2, $3, $4) RETURNING *',
            [product_id, user_name, rating, comment]
        );
        res.status(201).json({ message: 'Review submitted successfully. Awaiting admin approval.', review: result.rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Get all reviews (including unapproved)
app.get('/api/admin/reviews', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM reviews ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Approve a review
app.put('/api/admin/reviews/:id/approve', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('UPDATE reviews SET approved = true WHERE id = $1 RETURNING *', [req.params.id]);
        res.json({ message: 'Review approved', review: result.rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Delete a review (if inappropriate)
app.delete('/api/admin/reviews/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM reviews WHERE id = $1', [req.params.id]);
        res.json({ message: 'Review deleted' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
//               ADS & PROMOTIONS API
// ==========================================

// Public: Get active ads
app.get('/api/ads', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM ads WHERE active = true AND (end_date IS NULL OR end_date >= CURRENT_DATE)');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Create an ad
app.post('/api/admin/ads', verifyAdmin, async (req, res) => {
    const { title, description, image_url, start_date, end_date, active } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO ads (title, description, image_url, start_date, end_date, active) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [title, description, image_url, start_date, end_date, active]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Delete an ad
app.delete('/api/admin/ads/:id', verifyAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM ads WHERE id = $1', [req.params.id]);
        res.json({ message: 'Ad deleted' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
//               CONTACT & ORDERS API
// ==========================================

// Public: Submit Contact Form
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;
    // In a real app, you'd use Nodemailer or SendGrid here to send an email.
    console.log(`New contact message from ${name} (${email}): ${message}`);
    res.json({ success: true, message: 'Your message has been received!' });
});

// Public: Submit an Order (Checkout)
app.post('/api/orders', async (req, res) => {
    const { user_id, items, total_price } = req.body; // items is an array of { product_id, quantity, price }
    
    const client = await pool.connect(); // Use a transaction to ensure order and items save together
    try {
        await client.query('BEGIN');
        
        // 1. Create the Order
        const orderResult = await client.query(
            'INSERT INTO orders (user_id, total_price) VALUES ($1, $2) RETURNING id',
            [user_id || null, total_price]
        );
        const orderId = orderResult.rows[0].id;

        // 2. Insert Order Items and Update Stock
        for (let item of items) {
            await client.query(
                'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)',
                [orderId, item.product_id, item.quantity, item.price]
            );
            // Reduce stock
            await client.query(
                'UPDATE products SET stock = stock - $1 WHERE id = $2',
                [item.quantity, item.product_id]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ message: 'Order placed successfully!', orderId });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

// Admin: Get all orders
app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM orders ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});


app.get('/api/admin/orders/:id', verifyAdmin, async (req, res) => {
    try {
        // 1. Get Order Info
        const orderResult = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
        if (orderResult.rows.length === 0) return res.status(404).json({ error: 'Order not found' });

        // 2. Get the items for that order
        const itemsResult = await pool.query('SELECT * FROM order_items WHERE order_id = $1', [req.params.id]);
        
        const order = orderResult.rows[0];
        order.items = itemsResult.rows;

        res.json(order);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
//Analytics Endpoint for Admin Dashboard
app.get('/api/admin/analytics', verifyAdmin, async (req, res) => {
    try {
        // Get high-level stats
        const generalStats = await pool.query(`
            SELECT 
                COUNT(id) as "totalOrders", 
                SUM(total_price) as "totalRevenue" 
            FROM orders
        `);

        const itemsSold = await pool.query('SELECT SUM(quantity) as "totalItems" FROM order_items');

        // Get Top 5 Products by Sales
        const topProducts = await pool.query(`
            SELECT p.name, SUM(oi.quantity) as units_sold, SUM(oi.quantity * oi.price_at_purchase) as revenue
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            GROUP BY p.name
            ORDER BY units_sold DESC
            LIMIT 5
        `);

        res.json({
            totalOrders: generalStats.rows[0].totalOrders || 0,
            totalRevenue: generalStats.rows[0].totalRevenue || 0,
            totalItemsSold: itemsSold.rows[0].totalItems || 0,
            topProducts: topProducts.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PLACE ORDER ROUTE ---
app.post('/api/orders', async (req, res) => {
    const { customer_name, customer_email, shipping_address, total_price, items } = req.body;
    
    // Get a dedicated client for the transaction
    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // Start transaction

        // 1. Insert the main order record
        const orderRes = await client.query(
            `INSERT INTO orders (customer_name, customer_email, shipping_address, total_price, status) 
             VALUES ($1, $2, $3, $4, 'Pending') RETURNING id`,
            [customer_name, customer_email, shipping_address, total_price]
        );
        const newOrderId = orderRes.rows[0].id;

        // 2. Insert all items linked to this order
        for (let item of items) {
            await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) 
                 VALUES ($1, $2, $3, $4)`,
                [newOrderId, item.product_id, item.quantity, item.price]
            );

            // Optional: Reduce stock level
            // await client.query('UPDATE products SET stock = stock - $1 WHERE id = $2', [item.quantity, item.product_id]);
        }

        await client.query('COMMIT'); // Save transaction
        res.status(201).json({ message: 'Order placed successfully', orderId: newOrderId });

    } catch (err) {
        await client.query('ROLLBACK'); // Cancel transaction on error
        console.error("Checkout Error:", err);
        res.status(500).json({ error: 'Failed to process order' });
    } finally {
        client.release(); // Return client to the pool
    }
});

// --- ADMIN: UPDATE ORDER STATUS ---
app.put('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => {
    const { status } = req.body; // e.g., "Shipped", "Completed"
    try {
        await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
        res.json({ message: `Order marked as ${status}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET single order details for Admin
app.get('/api/admin/orders/:id', verifyAdmin, async (req, res) => {
    const orderId = req.params.id;

    try {
        // 1. Fetch the main order info
        const orderQuery = await pool.query(
            'SELECT * FROM orders WHERE id = $1', 
            [orderId]
        );

        if (orderQuery.rows.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // 2. Fetch the specific items in that order
        // We JOIN with products to get the product names instead of just IDs
        const itemsQuery = await pool.query(
            `SELECT oi.*, p.name as product_name 
             FROM order_items oi 
             JOIN products p ON oi.product_id = p.id 
             WHERE oi.order_id = $1`, 
            [orderId]
        );

        // Combine them into one response
        const orderData = orderQuery.rows[0];
        orderData.items = itemsQuery.rows;

        res.json(orderData);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error fetching order details' });
    }
});

// POST: Place a new order
app.post('/api/orders', async (req, res) => {
    const { customer_name, customer_email, customer_phone, shipping_address, total_price, items } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');
        const orderRes = await client.query(
            `INSERT INTO orders (customer_name, customer_email, customer_phone, shipping_address, total_price, status) 
             VALUES ($1, $2, $3, $4, $5, 'Pending') RETURNING id`,
            [customer_name, customer_email, customer_phone, shipping_address, total_price]
        );
        const orderId = orderRes.rows[0].id;

        for (let item of items) {
            await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)`,
                [orderId, item.product_id, item.quantity, item.price]
            );
        }
        await client.query('COMMIT');
        res.status(201).json({ message: 'Order created', orderId });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: err.message });
    } finally {
        client.release();
    }
});

// PUT: Admin updates order status (The "Response")
app.put('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => {
    const { status } = req.body; 
    try {
        await pool.query('UPDATE orders SET status = $1 WHERE id = $2', [status, req.params.id]);
        res.json({ message: `Order status updated to ${status}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// PUT: Admin updates order status
app.put('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    // 1. Define the allowed statuses exactly as they are in the database
    const allowedStatuses = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];

    // 2. Check if the incoming status is valid
    if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ 
            error: `Invalid status. Must be one of: ${allowedStatuses.join(', ')}` 
        });
    }

    try {
        // 3. Update the database
        const result = await pool.query(
            'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
            [status, id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: "Order not found" });
        }

        res.json({ 
            message: `Status successfully updated to ${status}`, 
            order: result.rows[0] 
        });
    } catch (err) {
        console.error("Database error during status update:", err);
        res.status(500).json({ error: "Failed to update status in the database." });
    }
});

// Public: Get only approved reviews
app.get('/api/reviews', async (req, res) => {
    const result = await pool.query('SELECT * FROM reviews WHERE approved = TRUE ORDER BY created_at DESC');
    res.json(result.rows);
});

// Public: Submit a new review (defaults to approved = false)
app.post('/api/reviews', async (req, res) => {
    const { user_name, rating, comment } = req.body;
    await pool.query('INSERT INTO reviews (user_name, rating, comment) VALUES ($1, $2, $3)', [user_name, rating, comment]);
    res.status(201).json({ message: "Submitted for review" });
});

// Admin: Approve a review
app.put('/api/admin/reviews/:id/approve', verifyAdmin, async (req, res) => {
    await pool.query('UPDATE reviews SET approved = TRUE WHERE id = $1', [req.params.id]);
    res.json({ message: "Review approved and visible" });
});
// --- SERVER LISTEN ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Coffee Shop Server is running on port ${PORT}`);
});