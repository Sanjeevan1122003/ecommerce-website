const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();
const port = 3000;

app.use(bodyParser.json());

const SECRET_KEY = 'E-commerce-website-jWt-@secretKeYs';

// MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Sandy@4253',
  database: 'ecommerce_db'
});

db.connect(err => {
  if (err) throw err;
  console.log('MySQL Connected.');
});

// Middleware for verifying JWT and role
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


// Auth routes
app.post('/register', async (req, res) => {
  const { username, email, password} = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query(
    'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
    [username, email, hashedPassword],
    err => {
      if (err) return res.status(500).send(err);
      res.send('User registered');
    }
  );
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err || results.length === 0) return res.sendStatus(401);
    const user = results[0];
    if (!(await bcrypt.compare(password, user.password))) return res.sendStatus(403);
    const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY);
    res.json({ token });
  });
});

// Product Routes
app.get('/products', (req, res) => {
  let sql = 'SELECT * FROM products';
  db.query(sql, (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.post('/admin/products', authenticateToken,(req, res) => {
  const { name, price, category } = req.body;
  db.query(
    'INSERT INTO products (name, price, category) VALUES (?, ?, ?)',
    [name, price, category],
    err => {
      if (err) return res.status(500).send(err);
      res.send('Product added');
    }
  );
});

app.put('/admin/products/:id', authenticateToken, (req, res) => {
  const { name, price, category } = req.body;
  db.query(
    'UPDATE products SET name=?, price=?, category=? WHERE id=?',
    [name, price, category, req.params.id],
    err => {
      if (err) return res.status(500).send(err);
      res.send('Product updated');
    }
  );
});

app.delete('admin/products/:id', authenticateToken,(req, res) => {
  db.query('DELETE FROM products WHERE id=?', [req.params.id], err => {
    if (err) return res.status(500).send(err);
    res.send('Product deleted');
  });
});

// Cart Routes
app.post('/cart', authenticateToken,(req, res) => {
  const { productId, quantity } = req.body;
  db.query(
    'INSERT INTO cart (email, product_id, quantity) VALUES (?, ?, ?)',
    [req.user.email, productId, quantity],
    err => {
      if (err) return res.status(500).send(err);
      res.send('Added to cart');
    }
  );
});

app.get('/cart', authenticateToken, (req, res) => {
  db.query(
    'SELECT c.id, p.name, c.quantity FROM cart c JOIN products p ON c.product_id = p.id WHERE c.email = ?',
    [req.user.email],
    (err, results) => {
      if (err) return res.status(500).send(err);
      res.json(results);
    }
  );
});

app.delete('/cart/:id', authenticateToken, (req, res) => {
  db.query('DELETE FROM cart WHERE id=? AND email=?', [req.params.id, req.user.email], err => {
    if (err) return res.status(500).send(err);
    res.send('Item removed from cart');
  });
});

// Order Route
app.post('/order', authenticateToken,(req, res) => {
  db.query(
    'INSERT INTO orders (email) VALUES (?)',
    [req.user.email],
    (err, result) => {
      if (err) return res.status(500).send(err);
      const orderId = result.insertId;
      db.query(
        'INSERT INTO order_items (order_id, product_id, quantity) SELECT ?, product_id, quantity FROM cart WHERE email=?',
        [orderId, req.user.email],
        err => {
          if (err) return res.status(500).send(err);
          db.query('DELETE FROM cart WHERE email=?', [req.user.email]);
          res.send('Order placed');
        }
      );
    }
  );
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/welcome/index.html'));
});

app.get("/home", authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/home/index.html'));
})
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));