require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');

const REQUIRED_ENV = [
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'JWT_SECRET',
  'ADMIN_REGISTRATION_SECRET',
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length) {
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const supabaseOptions = {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
  },
};

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  supabaseOptions
);

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  supabaseOptions
);

const ORDER_STATUSES = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const corsOptions = {
  origin: [
    'https://campobrew.onrender.com',
    'https://techsips-brew.onrender.com',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", 'https://cdn.tailwindcss.com', 'https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:', 'https://*'],
      connectSrc: ["'self'", 'https://campobrew.onrender.com', 'https://techsips-brew.onrender.com'],
    },
  })
);

function sendServerError(res, error, fallback = 'Server error') {
  console.error(error);
  return res.status(500).json({ error: error?.message || fallback });
}

async function runPublicRead(builderFactory) {
  const anonResult = await builderFactory(supabase);
  if (!anonResult.error) return anonResult;
  return builderFactory(supabaseAdmin);
}

function isMissingRowError(error) {
  return error?.code === 'PGRST116';
}

function normalizeIdList(items, key) {
  return [...new Set(items.map((item) => item[key]).filter(Boolean).map(String))];
}

async function fetchProductNameMap(productIds) {
  if (!productIds.length) return new Map();

  const { data, error } = await supabaseAdmin
    .from('products')
    .select('id, name')
    .in('id', productIds);

  if (error) throw error;

  return new Map((data || []).map((product) => [String(product.id), product.name]));
}

async function rollbackOrder(orderId, restoredStocks) {
  for (const product of restoredStocks) {
    await supabaseAdmin
      .from('products')
      .update({ stock: product.originalStock })
      .eq('id', product.id);
  }

  await supabaseAdmin.from('order_items').delete().eq('order_id', orderId);
  await supabaseAdmin.from('orders').delete().eq('id', orderId);
}

const verifyAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden. Admin access required.' });
    }

    req.user = decoded;
    next();
  });
};

app.get('/favicon.ico', (req, res) => res.status(204).end());

app.post('/api/admin/register', async (req, res) => {
  const { name, email, password, adminSecret } = req.body;

  if (adminSecret !== process.env.ADMIN_REGISTRATION_SECRET) {
    return res.status(403).json({ error: 'Invalid Admin Secret Key' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const { data, error } = await supabaseAdmin
      .from('users')
      .insert({
        name,
        email,
        password_hash: hashedPassword,
        role: 'admin',
      })
      .select('id, name, email')
      .single();

    if (error) {
      if (error.code === '23505') {
        return res.status(400).json({ error: 'Email already exists' });
      }

      return sendServerError(res, error);
    }

    res.status(201).json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data: user, error } = await supabaseAdmin
      .from('users')
      .select('*')
      .eq('email', email)
      .eq('role', 'admin')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token, user: { name: user.name, email: user.email } });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/products', async (req, res) => {
  const { category, search } = req.query;

  try {
    const { data, error } = await runPublicRead((client) => {
      let query = client
        .from('products')
        .select('*')
        .order('created_at', { ascending: false });

      if (category) query = query.eq('category', category);
      if (search) query = query.ilike('name', `%${search}%`);

      return query;
    });

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const { data, error } = await runPublicRead((client) =>
      client.from('products').select('*').eq('id', req.params.id).maybeSingle()
    );

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/admin/products', verifyAdmin, async (req, res) => {
  const { name, description, price, category, image_url, stock } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('products')
      .insert({ name, description, price, category, image_url, stock })
      .select('*')
      .single();

    if (error) return sendServerError(res, error);
    res.status(201).json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.put('/api/admin/products/:id', verifyAdmin, async (req, res) => {
  const { name, description, price, category, image_url, stock } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('products')
      .update({ name, description, price, category, image_url, stock })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/api/admin/products/:id', verifyAdmin, async (req, res) => {
  try {
    const { error } = await supabaseAdmin.from('products').delete().eq('id', req.params.id);
    if (error) return sendServerError(res, error);
    res.json({ message: 'Product successfully deleted' });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/blogs', async (req, res) => {
  try {
    const { data, error } = await runPublicRead((client) =>
      client.from('blogs').select('*').order('created_at', { ascending: false })
    );

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/admin/blogs', verifyAdmin, async (req, res) => {
  const { title, content, author, image_url } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('blogs')
      .insert({ title, content, author, image_url })
      .select('*')
      .single();

    if (error) return sendServerError(res, error);
    res.status(201).json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.put('/api/admin/blogs/:id', verifyAdmin, async (req, res) => {
  const { title, content, author, image_url } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('blogs')
      .update({ title, content, author, image_url })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Blog not found' });
    }

    res.json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/api/admin/blogs/:id', verifyAdmin, async (req, res) => {
  try {
    const { error } = await supabaseAdmin.from('blogs').delete().eq('id', req.params.id);
    if (error) return sendServerError(res, error);
    res.json({ message: 'Blog deleted' });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/reviews', async (req, res) => {
  try {
    const { data, error } = await runPublicRead((client) =>
      client
        .from('reviews')
        .select('*')
        .eq('approved', true)
        .order('created_at', { ascending: false })
    );

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/reviews/:productId', async (req, res) => {
  try {
    const { data, error } = await runPublicRead((client) =>
      client
        .from('reviews')
        .select('*')
        .eq('product_id', req.params.productId)
        .eq('approved', true)
        .order('created_at', { ascending: false })
    );

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/reviews', async (req, res) => {
  const { product_id, user_name, rating, comment } = req.body;
  const numericRating = Number(rating);

  if (!user_name || !comment) {
    return res.status(400).json({ error: 'user_name and comment are required' });
  }

  if (!Number.isInteger(numericRating) || numericRating < 1 || numericRating > 5) {
    return res.status(400).json({ error: 'rating must be an integer between 1 and 5' });
  }

  try {
    const payload = {
      user_name,
      rating: numericRating,
      comment,
    };

    if (product_id) {
      payload.product_id = product_id;
    }

    const { data, error } = await supabaseAdmin
      .from('reviews')
      .insert(payload)
      .select('*')
      .single();

    if (error) return sendServerError(res, error);

    res.status(201).json({
      message: 'Review submitted successfully. Awaiting admin approval.',
      review: data,
    });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/admin/reviews', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('reviews')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.put('/api/admin/reviews/:id/approve', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('reviews')
      .update({ approved: true })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Review not found' });
    }

    res.json({ message: 'Review approved', review: data });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/api/admin/reviews/:id', verifyAdmin, async (req, res) => {
  try {
    const { error } = await supabaseAdmin.from('reviews').delete().eq('id', req.params.id);
    if (error) return sendServerError(res, error);
    res.json({ message: 'Review deleted' });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/ads', async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const { data, error } = await runPublicRead((client) =>
      client
        .from('ads')
        .select('*')
        .eq('active', true)
        .or(`end_date.is.null,end_date.gte.${today}`)
        .order('start_date', { ascending: false, nullsFirst: false })
    );

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/admin/ads', verifyAdmin, async (req, res) => {
  const { title, description, image_url, start_date, end_date, active } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('ads')
      .insert({ title, description, image_url, start_date, end_date, active })
      .select('*')
      .single();

    if (error) return sendServerError(res, error);
    res.status(201).json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/admin/ads', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('ads')
      .select('*')
      .order('start_date', { ascending: false, nullsFirst: false });

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/admin/ads/:id', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('ads')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Ad not found' });
    }

    res.json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.put('/api/admin/ads/:id', verifyAdmin, async (req, res) => {
  const { title, description, image_url, start_date, end_date, active } = req.body;

  try {
    const { data, error } = await supabaseAdmin
      .from('ads')
      .update({ title, description, image_url, start_date, end_date, active })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Ad not found' });
    }

    res.json(data);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.delete('/api/admin/ads/:id', verifyAdmin, async (req, res) => {
  try {
    const { error } = await supabaseAdmin.from('ads').delete().eq('id', req.params.id);
    if (error) return sendServerError(res, error);
    res.json({ message: 'Ad deleted' });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body;
  console.log(`New contact message from ${name} (${email}): ${message}`);
  res.json({ success: true, message: 'Your message has been received!' });
});

app.post('/api/orders', async (req, res) => {
  const {
    user_id,
    customer_name,
    customer_email,
    customer_phone,
    shipping_address,
    items,
    total_price,
  } = req.body;

  const name = (customer_name || '').trim();
  const email = (customer_email || '').trim();
  const phone = (customer_phone || '').trim();
  const address = (shipping_address || '').trim();

  if (!name || !email || !phone || !address) {
    return res.status(400).json({
      error: 'Customer details are required (name, email, phone, address).',
    });
  }

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Order must include at least one item.' });
  }

  if (typeof total_price !== 'number' || Number.isNaN(total_price) || total_price <= 0) {
    return res.status(400).json({ error: 'Invalid total_price.' });
  }

  const parsedItems = items.map((item) => ({
    product_id: String(item.product_id),
    quantity: Number(item.quantity),
    price: Number(item.price),
  }));

  if (parsedItems.some((item) => !item.product_id || item.quantity <= 0 || item.price < 0)) {
    return res.status(400).json({ error: 'Each item must include valid product_id, quantity, and price.' });
  }

  const productIds = normalizeIdList(parsedItems, 'product_id');
  const quantityByProduct = new Map();
  for (const item of parsedItems) {
    quantityByProduct.set(
      item.product_id,
      (quantityByProduct.get(item.product_id) || 0) + item.quantity
    );
  }

  let orderId = null;
  const restoredStocks = [];

  try {
    const { data: products, error: productsError } = await supabaseAdmin
      .from('products')
      .select('id, name, stock')
      .in('id', productIds);

    if (productsError) return sendServerError(res, productsError);

    if ((products || []).length !== productIds.length) {
      return res.status(400).json({ error: 'One or more products do not exist.' });
    }

    for (const product of products) {
      const requestedQty = quantityByProduct.get(String(product.id)) || 0;
      if (product.stock < requestedQty) {
        return res.status(400).json({
          error: `Insufficient stock for ${product.name}. Available: ${product.stock}`,
        });
      }
    }

    const { data: order, error: orderError } = await supabaseAdmin
      .from('orders')
      .insert({
        user_id: user_id || null,
        customer_name: name,
        customer_email: email,
        customer_phone: phone,
        shipping_address: address,
        total_price,
        status: 'Pending',
      })
      .select('id')
      .single();

    if (orderError) return sendServerError(res, orderError);

    orderId = order.id;

    const orderItemsPayload = parsedItems.map((item) => ({
      order_id: orderId,
      product_id: item.product_id,
      quantity: item.quantity,
      price_at_purchase: item.price,
    }));

    const { error: itemsError } = await supabaseAdmin
      .from('order_items')
      .insert(orderItemsPayload);

    if (itemsError) {
      await rollbackOrder(orderId, restoredStocks);
      return sendServerError(res, itemsError);
    }

    for (const product of products) {
      const nextStock = product.stock - (quantityByProduct.get(String(product.id)) || 0);

      const { data: updatedProduct, error: stockError } = await supabaseAdmin
        .from('products')
        .update({ stock: nextStock })
        .eq('id', product.id)
        .eq('stock', product.stock)
        .select('id, stock')
        .maybeSingle();

      if (stockError && !isMissingRowError(stockError)) {
        await rollbackOrder(orderId, restoredStocks);
        return sendServerError(res, stockError);
      }

      if (!updatedProduct) {
        await rollbackOrder(orderId, restoredStocks);
        return res.status(409).json({
          error: `Stock changed while placing the order for ${product.name}. Please try again.`,
        });
      }

      restoredStocks.push({ id: product.id, originalStock: product.stock });
    }

    res.status(201).json({ message: 'Order placed successfully!', orderId });
  } catch (error) {
    if (orderId) {
      try {
        await rollbackOrder(orderId, restoredStocks);
      } catch (rollbackError) {
        console.error('Order rollback failed', rollbackError);
      }
    }

    sendServerError(res, error);
  }
});

app.get('/api/admin/orders', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from('orders')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) return sendServerError(res, error);
    res.json(data || []);
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get('/api/admin/orders/:id', verifyAdmin, async (req, res) => {
  try {
    const { data: order, error: orderError } = await supabaseAdmin
      .from('orders')
      .select('*')
      .eq('id', req.params.id)
      .maybeSingle();

    if (orderError && !isMissingRowError(orderError)) {
      return sendServerError(res, orderError);
    }

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const { data: orderItems, error: itemsError } = await supabaseAdmin
      .from('order_items')
      .select('*')
      .eq('order_id', req.params.id);

    if (itemsError) return sendServerError(res, itemsError);

    const productNameMap = await fetchProductNameMap(normalizeIdList(orderItems || [], 'product_id'));

    order.items = (orderItems || []).map((item) => ({
      ...item,
      product_name: productNameMap.get(String(item.product_id)) || 'Coffee Product',
    }));

    res.json(order);
  } catch (error) {
    sendServerError(res, error, 'Server error fetching order details');
  }
});

app.put('/api/admin/orders/:id/status', verifyAdmin, async (req, res) => {
  const { status } = req.body;

  if (!ORDER_STATUSES.includes(status)) {
    return res.status(400).json({
      error: `Invalid status. Must be one of: ${ORDER_STATUSES.join(', ')}`,
    });
  }

  try {
    const { data, error } = await supabaseAdmin
      .from('orders')
      .update({ status })
      .eq('id', req.params.id)
      .select('*')
      .maybeSingle();

    if (error && !isMissingRowError(error)) {
      return sendServerError(res, error);
    }

    if (!data) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json({
      message: `Status successfully updated to ${status}`,
      order: data,
    });
  } catch (error) {
    sendServerError(res, error, 'Failed to update status in the database.');
  }
});

app.get('/api/admin/analytics', verifyAdmin, async (req, res) => {
  try {
    const [{ data: orders, error: ordersError }, { data: orderItems, error: itemsError }] =
      await Promise.all([
        supabaseAdmin.from('orders').select('id, total_price'),
        supabaseAdmin.from('order_items').select('product_id, quantity, price_at_purchase'),
      ]);

    if (ordersError) return sendServerError(res, ordersError);
    if (itemsError) return sendServerError(res, itemsError);

    const productIds = normalizeIdList(orderItems || [], 'product_id');
    const productNameMap = await fetchProductNameMap(productIds);

    const topProductMap = new Map();
    for (const item of orderItems || []) {
      const productKey = String(item.product_id);
      const current = topProductMap.get(productKey) || {
        name: productNameMap.get(productKey) || 'Unknown Product',
        units_sold: 0,
        revenue: 0,
      };

      current.units_sold += Number(item.quantity) || 0;
      current.revenue += (Number(item.quantity) || 0) * (Number(item.price_at_purchase) || 0);
      topProductMap.set(productKey, current);
    }

    const topProducts = [...topProductMap.values()]
      .sort((a, b) => b.units_sold - a.units_sold)
      .slice(0, 5);

    const totalRevenue = (orders || []).reduce(
      (sum, order) => sum + (Number(order.total_price) || 0),
      0
    );

    const totalItemsSold = (orderItems || []).reduce(
      (sum, item) => sum + (Number(item.quantity) || 0),
      0
    );

    res.json({
      totalOrders: (orders || []).length,
      totalRevenue,
      totalItemsSold,
      topProducts,
    });
  } catch (error) {
    sendServerError(res, error);
  }
});

app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});
