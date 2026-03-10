const express = require('express');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const path = require('path');

// --- Firebase 設定 ---
// Renderの環境変数 FIREBASE_SERVICE_ACCOUNT にJSONの中身を入れてください
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
});
const db = admin.database();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- セッション設定 ---
app.use(session({
  secret: 'sennin-master-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1日
}));

// --- 認証用ミドルウェア ---
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
};

// --- APIルーティング ---

// 新規登録
app.post('/api/auth/register', async (req, res) => {
  const { userId, username, password } = req.body;
  if (!userId || !username || !password) return res.status(400).send('入力が不足しています');

  const userRef = db.ref('users/' + userId);
  const snapshot = await userRef.once('value');
  if (snapshot.exists()) return res.status(400).send('このIDは既に使用されています');

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    userId,
    username,
    password: hashedPassword,
    apiKey: uuidv4(),
    createdAt: new Date().toISOString()
  };

  await userRef.set(newUser);
  res.redirect('/');
});

// ログイン
app.post('/api/auth/login', async (req, res) => {
  const { userId, password } = req.body;
  const userRef = db.ref('users/' + userId);
  const snapshot = await userRef.once('value');
  const user = snapshot.val();

  if (user && await bcrypt.compare(password, user.password)) {
    req.session.userId = user.userId;
    res.redirect('/dashboard.html');
  } else {
    res.status(401).send('IDまたはパスワードが間違っています');
  }
});

// ログアウト
app.get('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// ユーザー情報取得
app.get('/api/user/me', isAuthenticated, async (req, res) => {
  const snapshot = await db.ref('users/' + req.session.userId).once('value');
  const user = snapshot.val();
  const { password, ...safeUser } = user; // パスワードを除外
  res.json(safeUser);
});

// APIキー再発行
app.post('/api/user/regen-key', isAuthenticated, async (req, res) => {
  const newKey = uuidv4();
  await db.ref('users/' + req.session.userId).update({ apiKey: newKey });
  res.json({ apiKey: newKey });
});

// 外部連携用API (SSO)
app.get('/api/external/userinfo', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Invalid API Key' });
  
  const apiKey = authHeader.split(' ')[1];
  const snapshot = await db.ref('users').orderByChild('apiKey').equalTo(apiKey).once('value');
  const userData = snapshot.val();

  if (!userData) return res.status(404).json({ error: 'User not found' });
  const user = Object.values(userData)[0];
  res.json({
    status: "success",
    data: { id: user.userId, name: user.username }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Sennin Account Running on port ${PORT}`));
