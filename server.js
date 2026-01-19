// ================================
// SERVIDOR DE COBRANZA + WHATSAPP MASIVO (CORREGIDO)
// Compatible con Render
// ================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const cron = require('node-cron');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const qrcode = require('qrcode');
const { Client: WhatsAppClient, LocalAuth } = require('whatsapp-web.js');
const twilio = require('twilio');

// ================================
// VALIDACIONES DE ENTORNO
// ================================
if (!process.env.MONGO_URI) {
  console.error('❌ MONGO_URI no está definida en las variables de entorno');
}

// ================================
// APP
// ================================
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;

// ================================
// MONGODB (CORREGIDO)
// ================================
mongoose.connect(process.env.MONGO_URI || '', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('💾 MongoDB conectado'))
.catch(err => console.error('❌ Error de MongoDB:', err));

// ================================
// SCHEMAS / MODELOS
// ================================

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  credits: { type: Number, default: 0 }
});

const clientSchema = new mongoose.Schema({
  name: String,
  phone: String,
  debt: Number,
  status: String
});

const campaignSchema = new mongoose.Schema({
  user: String,
  message: String,
  total: Number,
  sent: Number,
  errorsCount: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Client = mongoose.models.Client || mongoose.model('Client', clientSchema);
const Campaign = mongoose.models.Campaign || mongoose.model('Campaign', campaignSchema);

// ================================
// TWILIO
// ================================
const twilioClient = process.env.TWILIO_SID && process.env.TWILIO_TOKEN
  ? twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN)
  : null;
console.log('📞 Twilio configurado');

// ================================
// WHATSAPP (CORREGIDO PARA RENDER)
// ================================
let whatsappClient;

function initWhatsApp() {
  console.log('📱 Inicializando WhatsApp...');

  whatsappClient = new WhatsAppClient({
    authStrategy: new LocalAuth({
      dataPath: path.join(__dirname, 'whatsapp-session')
    }),
    restartOnAuthFail: true,
    puppeteer: {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--disable-gpu'
      ]
    }
  });

  whatsappClient.on('qr', qr => {
    console.log('📲 Escanea el QR de WhatsApp');
    qrcode.toString(qr, { type: 'terminal' }, (err, url) => {
      if (!err) console.log(url);
    });
  });

  whatsappClient.on('ready', () => {
    console.log('✅ WhatsApp listo');
  });

  whatsappClient.on('auth_failure', () => {
    console.log('⚠️ Fallo de autenticación WhatsApp, reintentando...');
  });

  whatsappClient.initialize();
}

initWhatsApp();

// ================================
// ENDPOINTS
// ================================

app.get('/', (req, res) => {
  res.send('🚀 Sistema de Cobranza activo');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

  res.json({ success: true });
});

app.post('/send-whatsapp', async (req, res) => {
  const { phone, message, username } = req.body;

  const user = await User.findOne({ username });
  if (!user || user.credits < 1) {
    return res.status(400).json({ error: 'Créditos insuficientes' });
  }

  try {
    await whatsappClient.sendMessage(`${phone}@c.us`, message);
    user.credits -= 1;
    await user.save();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Error enviando WhatsApp' });
  }
});

// ================================
// CRON
// ================================
cron.schedule('0 * * * *', () => {
  console.log('⏰ Tarea programada ejecutada');
});

// ================================
// SHUTDOWN LIMPIO
// ================================
process.on('SIGTERM', async () => {
  console.log('🛑 Cerrando servidor...');
  if (whatsappClient) {
    try { await whatsappClient.destroy(); } catch (e) {}
  }
  process.exit(0);
});

// ================================
// START
// ================================
app.listen(PORT, () => {
  console.log('════════════════════════════════════════════════');
  console.log('🚀 SERVIDOR DE COBRANZA + WHATSAPP MASIVO');
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log('════════════════════════════════════════════════');
});
