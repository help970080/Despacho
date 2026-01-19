const express = require('express');
const mongoose = require('mongoose');
const twilio = require('twilio');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CONEXION A MONGODB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cobranza-system')
.then(() => console.log('✅ Conectado a MongoDB'))
.catch(err => console.error('❌ Error conectando a MongoDB:', err));

// ═══════════════════════════════════════════════════════════════
// 📱 CONFIGURACIÓN WHATSAPP WEB.JS
// ═══════════════════════════════════════════════════════════════
let whatsappClient = null;
let whatsappReady = false;
let whatsappQR = null;
let whatsappInfo = null;

function initWhatsApp() {
  console.log('📱 Inicializando WhatsApp...');
  
  whatsappClient = new Client({
    authStrategy: new LocalAuth({ dataPath: './whatsapp-session' }),
    puppeteer: {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--disable-gpu'
      ]
    }
  });

  whatsappClient.on('qr', async (qr) => {
    console.log('📱 QR Code generado - escanea con WhatsApp');
    whatsappQR = await qrcode.toDataURL(qr);
    whatsappReady = false;
  });

  whatsappClient.on('ready', () => {
    console.log('✅ WhatsApp conectado y listo!');
    whatsappReady = true;
    whatsappQR = null;
    whatsappInfo = whatsappClient.info;
  });

  whatsappClient.on('authenticated', () => {
    console.log('🔐 WhatsApp autenticado');
  });

  whatsappClient.on('auth_failure', (msg) => {
    console.error('❌ Error de autenticación WhatsApp:', msg);
    whatsappReady = false;
  });

  whatsappClient.on('disconnected', (reason) => {
    console.log('📱 WhatsApp desconectado:', reason);
    whatsappReady = false;
    whatsappQR = null;
    // Reintentar conexión después de 5 segundos
    setTimeout(() => {
      console.log('🔄 Reintentando conexión WhatsApp...');
      whatsappClient.initialize();
    }, 5000);
  });

  whatsappClient.initialize();
}

// Iniciar WhatsApp al arrancar el servidor
initWhatsApp();

// ═══════════════════════════════════════════════════════════════
// MODELOS DE MONGODB
// ═══════════════════════════════════════════════════════════════
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  credits: { type: Number, default: 100 },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const templateSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  company: { type: String, required: true },
  name: { type: String, required: true },
  smsMessage: String,
  whatsappMessage: String, // NUEVO: Mensaje para WhatsApp
  callScript: String,
  provider: { type: String, enum: ['twilio', 'broadcaster', 'whatsapp'], default: 'twilio' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
});

const clientSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  cleanPhone: { type: String, required: true },
  debt: { type: String, default: '0' },
  company: String,
  status: { 
    type: String, 
    enum: ['pending', 'contacted', 'promised', 'paid', 'dispute'], 
    default: 'pending' 
  },
  notes: String,
  lastContact: Date,
  createdAt: { type: Date, default: Date.now }
});

const scheduledCampaignSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  name: { type: String, required: true },
  templateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Template' },
  type: { type: String, enum: ['sms', 'call', 'whatsapp'], required: true }, // AGREGADO whatsapp
  provider: { type: String, enum: ['twilio', 'broadcaster', 'whatsapp'], default: 'twilio' },
  scheduledDate: { type: Date, required: true },
  clients: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Client' }],
  status: { 
    type: String, 
    enum: ['scheduled', 'running', 'completed', 'cancelled'], 
    default: 'scheduled' 
  },
  // Configuración específica para WhatsApp
  whatsappConfig: {
    delayMin: { type: Number, default: 20 },  // Delay mínimo entre mensajes (segundos)
    delayMax: { type: Number, default: 45 },  // Delay máximo entre mensajes (segundos)
    batchSize: { type: Number, default: 50 }, // Mensajes por lote
    batchDelay: { type: Number, default: 120 } // Pausa entre lotes (segundos)
  },
  results: {
    total: { type: Number, default: 0 },
    success: { type: Number, default: 0 },
    errors: { type: Number, default: 0 }
  },
  createdAt: { type: Date, default: Date.now },
  executedAt: Date
});

const statsSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  total: { type: Number, default: 0 },
  success: { type: Number, default: 0 },
  errors: { type: Number, default: 0 },
  pending: { type: Number, default: 0 },
  callAnswered: { type: Number, default: 0 },
  callRejected: { type: Number, default: 0 },
  callBusy: { type: Number, default: 0 },
  callNoAnswer: { type: Number, default: 0 },
  whatsappSent: { type: Number, default: 0 },      // NUEVO
  whatsappDelivered: { type: Number, default: 0 }, // NUEVO
  whatsappFailed: { type: Number, default: 0 },    // NUEVO
  lastUpdated: { type: Date, default: Date.now }
});

const activityLogSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'error'], default: 'info' },
  timestamp: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  type: { type: String, enum: ['add', 'deduct', 'purchase', 'usage'], required: true },
  amount: { type: Number, required: true },
  balanceBefore: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  description: { type: String, required: true },
  adminUser: { type: String },
  reference: { type: String },
  timestamp: { type: Date, default: Date.now }
});

const callHistorySchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'Client' },
  clientName: String,
  phone: String,
  type: { type: String, enum: ['sms', 'call', 'whatsapp'], required: true }, // AGREGADO whatsapp
  status: { 
    type: String, 
    enum: ['completed', 'answered', 'busy', 'no-answer', 'failed', 'rejected', 'sent', 'delivered', 'undelivered', 'read'],
    required: true 
  },
  duration: { type: Number, default: 0 },
  cost: { type: Number, default: 0 },
  provider: { type: String, enum: ['twilio', 'broadcaster', 'whatsapp'] },
  campaignId: { type: mongoose.Schema.Types.ObjectId, ref: 'ScheduledCampaign' },
  timestamp: { type: Date, default: Date.now, index: true }
});

const User = mongoose.model('User', userSchema);
const Template = mongoose.model('Template', templateSchema);
const Client = mongoose.model('Client', clientSchema);
const ScheduledCampaign = mongoose.model('ScheduledCampaign', scheduledCampaignSchema);
const Stats = mongoose.model('Stats', statsSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const CallHistory = mongoose.model('CallHistory', callHistorySchema);

// CREAR USUARIO ADMIN INICIAL
async function createAdminUser() {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CAMBIAR_INMEDIATAMENTE';
      const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        name: 'SuperAdministrador',
        email: 'admin@sistema.com',
        credits: 10000,
        role: 'admin'
      });
      console.log('✅ Usuario admin creado');
    }
  } catch (error) {
    console.error('❌ Error creando admin:', error);
  }
}
createAdminUser();

// CONFIGURACION TWILIO
const ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_SMS = process.env.TWILIO_PHONE_SMS;
const TWILIO_PHONE_CALL = process.env.TWILIO_PHONE_CALL;
const BASE_URL = process.env.RENDER_EXTERNAL_URL || process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

let twilioClient = null;
if (ACCOUNT_SID && AUTH_TOKEN) {
  twilioClient = twilio(ACCOUNT_SID, AUTH_TOKEN);
  console.log('✅ Twilio configurado');
} else {
  console.log('⚠️ Twilio no configurado');
}

// CONFIGURACION BROADCASTER
const BROADCASTER_API_KEY = process.env.BROADCASTER_API_KEY;
const BROADCASTER_AUTHORIZATION = process.env.BROADCASTER_AUTHORIZATION;
const BROADCASTER_SMS_URL = 'https://api.broadcastermobile.com/brdcstr-endpoint-web/services/messaging/';
const BROADCASTER_VOICE_URL = 'https://api.broadcastermobile.com/broadcaster-voice-api/services/voice/sendCall';

if (BROADCASTER_API_KEY && BROADCASTER_AUTHORIZATION) {
  console.log('✅ Broadcaster configurado');
}

// CONFIGURACION PROXY
const PROXY_URL = process.env.QUOTAGUARDSTATIC_URL || process.env.FIXIE_URL || null;
let axiosConfig = {};
if (PROXY_URL) {
  const httpsAgent = new HttpsProxyAgent(PROXY_URL);
  axiosConfig = { httpsAgent, proxy: false };
  console.log('✅ Proxy configurado');
}

// ═══════════════════════════════════════════════════════════════
// 📱 ENDPOINTS DE WHATSAPP
// ═══════════════════════════════════════════════════════════════

// Estado de WhatsApp
app.get('/api/whatsapp/status', (req, res) => {
  res.json({
    success: true,
    connected: whatsappReady,
    qrCode: whatsappQR,
    info: whatsappInfo ? {
      number: whatsappInfo.wid?.user,
      name: whatsappInfo.pushname
    } : null
  });
});

// Desconectar WhatsApp
app.post('/api/whatsapp/disconnect', async (req, res) => {
  try {
    if (whatsappClient) {
      await whatsappClient.logout();
      whatsappReady = false;
      whatsappQR = null;
      whatsappInfo = null;
    }
    res.json({ success: true, message: 'WhatsApp desconectado' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Reiniciar WhatsApp
app.post('/api/whatsapp/restart', async (req, res) => {
  try {
    if (whatsappClient) {
      await whatsappClient.destroy();
    }
    whatsappReady = false;
    whatsappQR = null;
    initWhatsApp();
    res.json({ success: true, message: 'WhatsApp reiniciando...' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Enviar mensaje individual de WhatsApp
app.post('/api/send-whatsapp', async (req, res) => {
  try {
    const { to, message, username } = req.body;
    
    if (!whatsappReady) {
      return res.status(400).json({ 
        success: false, 
        error: 'WhatsApp no está conectado. Escanea el código QR primero.' 
      });
    }
    
    // Formatear número para WhatsApp (52 + 10 dígitos + @c.us)
    let cleanNumber = to.replace(/\D/g, '');
    if (cleanNumber.startsWith('52')) {
      cleanNumber = cleanNumber.substring(2);
    }
    if (cleanNumber.length !== 10) {
      return res.status(400).json({ success: false, error: 'Número debe tener 10 dígitos' });
    }
    
    const whatsappNumber = `52${cleanNumber}@c.us`;
    
    // Verificar si el número existe en WhatsApp
    const isRegistered = await whatsappClient.isRegisteredUser(whatsappNumber);
    if (!isRegistered) {
      // Registrar como fallido
      await CallHistory.create({
        username,
        phone: to,
        type: 'whatsapp',
        status: 'failed',
        provider: 'whatsapp'
      });
      
      await Stats.updateOne(
        { username },
        { $inc: { whatsappFailed: 1, errors: 1 }, lastUpdated: new Date() },
        { upsert: true }
      );
      
      return res.status(400).json({ 
        success: false, 
        error: 'Este número no tiene WhatsApp registrado' 
      });
    }
    
    // Enviar mensaje
    const result = await whatsappClient.sendMessage(whatsappNumber, message);
    
    // Registrar en historial
    await CallHistory.create({
      username,
      phone: to,
      type: 'whatsapp',
      status: 'sent',
      provider: 'whatsapp'
    });
    
    // Actualizar estadísticas
    await Stats.updateOne(
      { username },
      { 
        $inc: { total: 1, whatsappSent: 1, success: 1 },
        lastUpdated: new Date()
      },
      { upsert: true }
    );
    
    // Descontar crédito (WhatsApp = 0.5 créditos, más barato que SMS)
    await User.findOneAndUpdate(
      { username },
      { $inc: { credits: -0.5 } }
    );
    
    res.json({ 
      success: true, 
      messageId: result.id._serialized,
      status: 'sent'
    });
    
  } catch (error) {
    console.error('❌ Error enviando WhatsApp:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Envío masivo de WhatsApp con delays
app.post('/api/send-whatsapp-bulk', async (req, res) => {
  try {
    const { clients, message, username, config } = req.body;
    
    if (!whatsappReady) {
      return res.status(400).json({ 
        success: false, 
        error: 'WhatsApp no está conectado' 
      });
    }
    
    // Configuración de delays
    const delayMin = config?.delayMin || 20;  // segundos
    const delayMax = config?.delayMax || 45;  // segundos
    const batchSize = config?.batchSize || 50;
    const batchDelay = config?.batchDelay || 120; // segundos
    
    // Iniciar envío en background
    res.json({ 
      success: true, 
      message: `Iniciando envío a ${clients.length} contactos`,
      config: { delayMin, delayMax, batchSize, batchDelay }
    });
    
    // Proceso de envío asíncrono
    (async () => {
      let sent = 0;
      let failed = 0;
      let currentBatch = 0;
      
      for (let i = 0; i < clients.length; i++) {
        const client = clients[i];
        
        try {
          // Formatear número
          let cleanNumber = (client.cleanPhone || client.phone).replace(/\D/g, '');
          if (cleanNumber.startsWith('52')) {
            cleanNumber = cleanNumber.substring(2);
          }
          
          if (cleanNumber.length !== 10) {
            failed++;
            continue;
          }
          
          const whatsappNumber = `52${cleanNumber}@c.us`;
          
          // Verificar registro
          const isRegistered = await whatsappClient.isRegisteredUser(whatsappNumber);
          if (!isRegistered) {
            failed++;
            await CallHistory.create({
              username,
              clientId: client._id,
              clientName: client.name,
              phone: client.phone,
              type: 'whatsapp',
              status: 'failed',
              provider: 'whatsapp'
            });
            continue;
          }
          
          // Personalizar mensaje
          const personalizedMessage = message
            .replace(/\{Nombre\}/g, client.name || '')
            .replace(/\{Telefono\}/g, client.phone || '')
            .replace(/\{Deuda\}/g, client.debt || '0')
            .replace(/\{Compañia\}/g, client.company || '');
          
          // Enviar
          await whatsappClient.sendMessage(whatsappNumber, personalizedMessage);
          sent++;
          
          // Registrar éxito
          await CallHistory.create({
            username,
            clientId: client._id,
            clientName: client.name,
            phone: client.phone,
            type: 'whatsapp',
            status: 'sent',
            provider: 'whatsapp'
          });
          
          // Log de progreso
          console.log(`📱 WhatsApp ${sent}/${clients.length}: ${client.name} ✅`);
          
          // Delay aleatorio entre mensajes
          const delay = Math.floor(Math.random() * (delayMax - delayMin + 1) + delayMin) * 1000;
          await new Promise(resolve => setTimeout(resolve, delay));
          
          // Pausa entre lotes
          currentBatch++;
          if (currentBatch >= batchSize && i < clients.length - 1) {
            console.log(`⏸️ Pausa de ${batchDelay}s después de ${batchSize} mensajes...`);
            await new Promise(resolve => setTimeout(resolve, batchDelay * 1000));
            currentBatch = 0;
          }
          
        } catch (error) {
          console.error(`❌ Error enviando a ${client.name}:`, error.message);
          failed++;
        }
      }
      
      // Actualizar estadísticas finales
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            total: sent + failed,
            whatsappSent: sent,
            whatsappFailed: failed,
            success: sent,
            errors: failed
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
      
      // Descontar créditos
      await User.findOneAndUpdate(
        { username },
        { $inc: { credits: -(sent * 0.5) } }
      );
      
      // Log final
      await ActivityLog.create({
        username,
        message: `📱 Campaña WhatsApp completada: ${sent} enviados, ${failed} fallidos`,
        type: sent > failed ? 'success' : 'error'
      });
      
      console.log(`✅ Campaña WhatsApp finalizada: ${sent} enviados, ${failed} fallidos`);
      
    })();
    
  } catch (error) {
    console.error('❌ Error en envío masivo:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// ENDPOINTS DE AUTENTICACION
// ═══════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Credenciales invalidas' });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Credenciales invalidas' });
    }
    user.lastLogin = new Date();
    await user.save();
    res.json({
      success: true,
      user: {
        username: user.username,
        name: user.name,
        email: user.email,
        credits: user.credits,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE USUARIOS
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, '-password').sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const { username, password, name, email, credits, role } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Usuario ya existe' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, password: hashedPassword, name, email, credits, role });
    await Stats.create({ username });
    res.json({ success: true, user: { ...newUser.toObject(), password: undefined } });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    if (username === 'admin') {
      return res.status(400).json({ success: false, error: 'No se puede eliminar al admin' });
    }
    await User.deleteOne({ username });
    await Template.deleteMany({ username });
    await Client.deleteMany({ username });
    await ScheduledCampaign.deleteMany({ username });
    await Stats.deleteOne({ username });
    await ActivityLog.deleteMany({ username });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE PLANTILLAS
app.get('/api/templates/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const templates = await Template.find({ username }).sort({ createdAt: -1 });
    res.json({ success: true, templates });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/templates', async (req, res) => {
  try {
    const { username, company, name, smsMessage, whatsappMessage, callScript, provider } = req.body;
    const template = await Template.create({
      username, company, name, smsMessage, whatsappMessage, callScript,
      provider: provider || 'twilio',
      updatedAt: new Date()
    });
    res.json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/templates/:id', async (req, res) => {
  try {
    await Template.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE CLIENTES
app.get('/api/clients/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const clients = await Client.find({ username }).sort({ createdAt: -1 });
    res.json({ success: true, clients });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/clients/bulk', async (req, res) => {
  try {
    const { username, clients } = req.body;
    const clientDocs = clients.map(c => ({
      username,
      name: c.Nombre,
      phone: c.Telefono,
      cleanPhone: c.cleanPhone,
      debt: c.Deuda,
      company: c.Compañia
    }));
    await Client.deleteMany({ username });
    const inserted = await Client.insertMany(clientDocs);
    res.json({ success: true, count: inserted.length });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE ESTADISTICAS
app.get('/api/stats/:username', async (req, res) => {
  try {
    const { username } = req.params;
    let stats = await Stats.findOne({ username });
    if (!stats) {
      stats = await Stats.create({ username });
    }
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE LOGS
app.get('/api/logs/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const logs = await ActivityLog.find({ username }).sort({ timestamp: -1 }).limit(100);
    res.json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/logs', async (req, res) => {
  try {
    const { username, message, type } = req.body;
    const log = await ActivityLog.create({ username, message, type });
    res.json({ success: true, log });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// FUNCIONES DE ENVIO SMS/LLAMADAS (existentes)
// ═══════════════════════════════════════════════════════════════
async function sendBroadcasterSMS(phoneNumber, message) {
  let cleanNumber = phoneNumber.replace(/\D/g, '');
  if (cleanNumber.startsWith('52')) cleanNumber = cleanNumber.substring(2);
  if (cleanNumber.length !== 10) throw new Error('Numero debe tener 10 digitos');

  const response = await axios.post(BROADCASTER_SMS_URL, {
    apiKey: parseInt(BROADCASTER_API_KEY),
    country: 'MX',
    dial: 41414,
    message: message,
    msisdns: [parseInt(`52${cleanNumber}`)],
    tag: 'sistema-cobranza'
  }, {
    ...axiosConfig,
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': BROADCASTER_AUTHORIZATION
    }
  });

  return { success: true, data: response.data };
}

async function sendBroadcasterCall(phoneNumber, message) {
  let cleanNumber = phoneNumber.replace(/\D/g, '');
  if (cleanNumber.startsWith('52')) cleanNumber = cleanNumber.substring(2);
  if (cleanNumber.length !== 10) throw new Error('Numero debe tener 10 digitos');

  const response = await axios.post(BROADCASTER_VOICE_URL, {
    phoneNumber: `52${cleanNumber}`,
    country: 'MX',
    message: { text: message, volume: 0, emphasis: 0, speed: 0, voice: 'Mia' }
  }, {
    ...axiosConfig,
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'api-key': '5031',
      'Authorization': BROADCASTER_AUTHORIZATION
    }
  });

  return { success: true, data: response.data };
}

// ENDPOINT ENVIAR SMS
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message, username, provider } = req.body;
    const selectedProvider = provider || 'twilio';
    let result;
    
    if (selectedProvider === 'broadcaster') {
      result = await sendBroadcasterSMS(to, message);
      await Stats.updateOne({ username }, { $inc: { total: 1, pending: 1 }, lastUpdated: new Date() }, { upsert: true });
    } else {
      if (!twilioClient) throw new Error('Twilio no configurado');
      result = await twilioClient.messages.create({
        body: message,
        from: TWILIO_PHONE_SMS,
        to: to,
        statusCallback: `${BASE_URL}/api/sms-status?username=${encodeURIComponent(username)}`
      });
    }
    
    await User.findOneAndUpdate({ username }, { $inc: { credits: -1 } });
    res.json({ success: true, provider: selectedProvider, sid: result.sid || 'broadcaster-' + Date.now(), status: result.status || 'sent' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINT HACER LLAMADA
app.post('/api/make-call', async (req, res) => {
  try {
    const { to, script, username, provider } = req.body;
    const selectedProvider = provider || 'twilio';
    let result;
    
    if (selectedProvider === 'broadcaster') {
      result = await sendBroadcasterCall(to, script);
      await Stats.updateOne({ username }, { $inc: { total: 1, pending: 1 }, lastUpdated: new Date() }, { upsert: true });
    } else {
      if (!twilioClient) throw new Error('Twilio no configurado');
      const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Mia" language="es-MX">${script}</Say>
  <Pause length="1"/>
  <Say voice="Polly.Mia" language="es-MX">Para mas informacion, comuniquese con nosotros. Gracias.</Say>
</Response>`;
      result = await twilioClient.calls.create({
        twiml: twiml,
        from: TWILIO_PHONE_CALL,
        to: to,
        statusCallback: `${BASE_URL}/api/call-status?username=${encodeURIComponent(username)}`,
        statusCallbackEvent: ['completed']
      });
    }
    
    await User.findOneAndUpdate({ username }, { $inc: { credits: -2 } });
    res.json({ success: true, provider: selectedProvider, sid: result.sid || 'broadcaster-' + Date.now(), status: result.status || 'sent' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// WEBHOOKS TWILIO
app.post('/api/call-status', async (req, res) => {
  try {
    const { CallStatus, CallSid, To, CallDuration } = req.body;
    const username = req.query.username;
    if (!username) return res.sendStatus(200);
    
    const duration = parseInt(CallDuration) || 0;
    await CallHistory.create({
      username, phone: To, type: 'call',
      status: CallStatus === 'completed' && duration > 0 ? 'answered' 
             : CallStatus === 'completed' && duration === 0 ? 'no-answer'
             : CallStatus === 'busy' ? 'busy' : CallStatus === 'failed' ? 'failed' : 'rejected',
      duration, cost: 2, provider: 'twilio'
    });
    
    if (CallStatus === 'completed') {
      await Stats.updateOne({ username }, { 
        $inc: { success: 1, callAnswered: duration > 0 ? 1 : 0, callNoAnswer: duration === 0 ? 1 : 0, pending: -1 },
        lastUpdated: new Date()
      }, { upsert: true });
    }
    res.sendStatus(200);
  } catch (error) {
    res.sendStatus(200);
  }
});

app.post('/api/sms-status', async (req, res) => {
  try {
    const { MessageStatus, To } = req.body;
    const username = req.query.username;
    if (!username) return res.sendStatus(200);
    
    if (MessageStatus === 'delivered') {
      await Stats.updateOne({ username }, { $inc: { success: 1, pending: -1 }, lastUpdated: new Date() }, { upsert: true });
    } else if (['failed', 'undelivered'].includes(MessageStatus)) {
      await Stats.updateOne({ username }, { $inc: { errors: 1, pending: -1 }, lastUpdated: new Date() }, { upsert: true });
    }
    res.sendStatus(200);
  } catch (error) {
    res.sendStatus(200);
  }
});

// HISTORIAL
app.get('/api/call-history/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { limit = 50, type, status } = req.query;
    let query = { username };
    if (type) query.type = type;
    if (status) query.status = status;
    const history = await CallHistory.find(query).sort({ timestamp: -1 }).limit(parseInt(limit)).lean();
    res.json({ success: true, history });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ═══════════════════════════════════════════════════════════════
// INICIAR SERVIDOR
// ═══════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('════════════════════════════════════════════════');
  console.log('🚀 SERVIDOR DE COBRANZA + WHATSAPP MASIVO');
  console.log('════════════════════════════════════════════════');
  console.log(`🌐 URL: ${BASE_URL}`);
  console.log(`💾 MongoDB: Conectando...`);
  console.log(`📞 Twilio: ${twilioClient ? 'Configurado ✅' : 'No configurado ⚠️'}`);
  console.log(`📡 Broadcaster: ${BROADCASTER_API_KEY ? 'Configurado ✅' : 'No configurado ⚠️'}`);
  console.log(`📱 WhatsApp: Inicializando...`);
  console.log('════════════════════════════════════════════════\n');
});