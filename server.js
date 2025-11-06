const express = require('express');
const mongoose = require('mongoose');
const twilio = require('twilio');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const { HttpsProxyAgent } = require('https-proxy-agent');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CONEXION A MONGODB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cobranza-system')
.then(() => console.log('✅ Conectado a MongoDB'))
.catch(err => console.error('❌ Error conectando a MongoDB:', err));

// MODELOS DE MONGODB
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
  callScript: String,
  provider: { type: String, enum: ['twilio', 'broadcaster'], default: 'twilio' },
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
  type: { type: String, enum: ['sms', 'call'], required: true },
  provider: { type: String, enum: ['twilio', 'broadcaster'], default: 'twilio' },
  scheduledDate: { type: Date, required: true },
  clients: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Client' }],
  status: { 
    type: String, 
    enum: ['scheduled', 'running', 'completed', 'cancelled'], 
    default: 'scheduled' 
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
  type: { type: String, enum: ['sms', 'call'], required: true },
  status: { 
    type: String, 
    enum: ['completed', 'answered', 'busy', 'no-answer', 'failed', 'rejected', 'sent', 'delivered', 'undelivered'],
    required: true 
  },
  duration: { type: Number, default: 0 },
  cost: { type: Number, default: 0 },
  provider: { type: String, enum: ['twilio', 'broadcaster'] },
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
      console.log('✅ Usuario admin creado: admin / [password desde variable de entorno]');
      if (!process.env.ADMIN_PASSWORD) {
        console.log('⚠️  ADVERTENCIA: Agrega ADMIN_PASSWORD a las variables de entorno');
      }
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
  console.log('⚠️  Twilio no configurado (variables de entorno faltantes)');
}

// CONFIGURACION BROADCASTER
const BROADCASTER_API_KEY = process.env.BROADCASTER_API_KEY;
const BROADCASTER_AUTHORIZATION = process.env.BROADCASTER_AUTHORIZATION;
const BROADCASTER_SMS_URL = 'https://api.broadcastermobile.com/brdcstr-endpoint-web/services/messaging/';
const BROADCASTER_VOICE_URL = 'https://api.broadcastermobile.com/broadcaster-voice-api/services/voice/sendCall';

if (BROADCASTER_API_KEY && BROADCASTER_AUTHORIZATION) {
  console.log('✅ Broadcaster configurado');
} else {
  console.log('⚠️  Broadcaster no configurado (faltan variables de entorno)');
}

// CONFIGURACION PROXY ESTATICO
const PROXY_URL = process.env.QUOTAGUARDSTATIC_URL || process.env.FIXIE_URL || null;

let axiosConfig = {};

if (PROXY_URL) {
  const proxyUrl = new URL(PROXY_URL);
  console.log(`✅ Proxy estático configurado: ${proxyUrl.hostname}:${proxyUrl.port || 80}`);
  
  const httpsAgent = new HttpsProxyAgent(PROXY_URL);
  
  axiosConfig = {
    httpsAgent: httpsAgent,
    proxy: false
  };
  
  console.log('🔒 Todas las peticiones salientes usarán IP estática del proxy');
} else {
  console.log('⚠️  Proxy NO configurado - usando IP dinámica de Render');
}

// ENDPOINTS DE AUTENTICACION
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
    const newUser = await User.create({
      username,
      password: hashedPassword,
      name,
      email,
      credits,
      role
    });
    
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
    const { username, company, name, smsMessage, callScript, provider } = req.body;
    
    const template = await Template.create({
      username,
      company,
      name,
      smsMessage,
      callScript,
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
    const { id } = req.params;
    await Template.findByIdAndDelete(id);
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

// ENDPOINTS DE CAMPAÑAS PROGRAMADAS
app.get('/api/scheduled-campaigns/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const campaigns = await ScheduledCampaign.find({ username })
      .populate('templateId')
      .populate('clients')
      .sort({ scheduledDate: -1 });
    
    const campaignsWithClientCount = campaigns.map(c => ({
      ...c.toObject(),
      results: {
        total: c.clients.length,
        success: c.results.success || 0,
        errors: c.results.errors || 0
      }
    }));
    
    res.json({ success: true, campaigns: campaignsWithClientCount });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/scheduled-campaigns', async (req, res) => {
  try {
    const { username, name, templateId, type, scheduledDate, clientIds, provider } = req.body;
    
    const campaign = await ScheduledCampaign.create({
      username,
      name,
      templateId,
      type,
      provider: provider || 'twilio',
      scheduledDate,
      clients: clientIds,
      status: 'scheduled',
      results: {
        total: clientIds.length,
        success: 0,
        errors: 0
      }
    });
    
    res.json({ success: true, campaign });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/scheduled-campaigns/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await ScheduledCampaign.findByIdAndUpdate(id, { status: 'cancelled' });
    res.json({ success: true });
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

app.post('/api/stats/:username/update', async (req, res) => {
  try {
    const { username } = req.params;
    const updates = req.body;
    
    const stats = await Stats.findOneAndUpdate(
      { username },
      { ...updates, lastUpdated: new Date() },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINTS DE LOGS
app.get('/api/logs/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const logs = await ActivityLog.find({ username })
      .sort({ timestamp: -1 })
      .limit(50);
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

// FUNCIONES DE ENVIO - BROADCASTER
async function sendBroadcasterSMS(phoneNumber, message) {
  try {
    let cleanNumber = phoneNumber.replace(/\D/g, '');
    if (cleanNumber.startsWith('52')) {
      cleanNumber = cleanNumber.substring(2);
    }
    if (cleanNumber.length !== 10) {
      throw new Error('Numero debe tener 10 digitos');
    }

    const requestBody = {
      apiKey: parseInt(BROADCASTER_API_KEY),
      country: 'MX',
      dial: 41414,
      message: message,
      msisdns: [parseInt(`52${cleanNumber}`)],
      tag: 'sistema-cobranza'
    };

    const response = await axios.post(BROADCASTER_SMS_URL, requestBody, {
      ...axiosConfig,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': BROADCASTER_AUTHORIZATION
      }
    });

    console.log('✅ SMS Broadcaster enviado:', response.status);
    return { success: true, data: response.data };
  } catch (error) {
    console.error('❌ Error enviando SMS con Broadcaster:', error.response?.data || error.message);
    throw error;
  }
}

async function sendBroadcasterCall(phoneNumber, message) {
  try {
    let cleanNumber = phoneNumber.replace(/\D/g, '');
    if (cleanNumber.startsWith('52')) {
      cleanNumber = cleanNumber.substring(2);
    }
    if (cleanNumber.length !== 10) {
      throw new Error('Numero debe tener 10 digitos');
    }

    const requestBody = {
      phoneNumber: `52${cleanNumber}`,
      country: 'MX',
      message: {
        text: message,
        volume: 0,
        emphasis: 0,
        speed: 0,
        voice: 'Mia'
      }
    };

    const response = await axios.post(BROADCASTER_VOICE_URL, requestBody, {
      ...axiosConfig,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'api-key': '5031',
        'Authorization': BROADCASTER_AUTHORIZATION
      }
    });

    console.log('✅ Llamada Broadcaster realizada:', response.status);
    return { success: true, data: response.data };
  } catch (error) {
    console.error('❌ Error enviando llamada con Broadcaster:', error.response?.data || error.message);
    throw error;
  }
}

// ENDPOINTS HIBRIDOS DE ENVIO
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message, username, provider } = req.body;
    const selectedProvider = provider || 'twilio';
    
    let result;
    
    if (selectedProvider === 'broadcaster') {
      result = await sendBroadcasterSMS(to, message);
      
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            total: 1,
            pending: 1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
      
    } else {
      if (!twilioClient) {
        throw new Error('Twilio no configurado');
      }
      
      result = await twilioClient.messages.create({
        body: message,
        from: TWILIO_PHONE_SMS,
        to: to,
        statusCallback: `${BASE_URL}/api/sms-status?username=${encodeURIComponent(username)}`
      });
    }
    
    await User.findOneAndUpdate(
      { username },
      { $inc: { credits: -1 } }
    );
    
    res.json({ 
      success: true, 
      provider: selectedProvider,
      sid: result.sid || 'broadcaster-' + Date.now(),
      status: result.status || 'sent'
    });
  } catch (error) {
    console.error('Error enviando SMS:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/make-call', async (req, res) => {
  try {
    const { to, script, username, provider } = req.body;
    const selectedProvider = provider || 'twilio';
    
    let result;
    
    if (selectedProvider === 'broadcaster') {
      result = await sendBroadcasterCall(to, script);
      
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            total: 1,
            pending: 1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
      
    } else {
      if (!twilioClient) {
        throw new Error('Twilio no configurado');
      }
      
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
    
    await User.findOneAndUpdate(
      { username },
      { $inc: { credits: -2 } }
    );
    
    res.json({ 
      success: true,
      provider: selectedProvider,
      sid: result.sid || 'broadcaster-' + Date.now(),
      status: result.status || 'sent'
    });
  } catch (error) {
    console.error('Error enviando llamada:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// WEBHOOKS TWILIO
app.post('/api/call-status', async (req, res) => {
  try {
    const { CallStatus, CallSid, To, CallDuration } = req.body;
    const username = req.query.username;
    
    console.log(`Llamada ${CallSid} a ${To}: ${CallStatus} (${CallDuration || 0}s) - Usuario: ${username}`);
    
    if (!username) {
      console.error('Username no proporcionado en webhook');
      return res.sendStatus(200);
    }
    
    const duration = parseInt(CallDuration) || 0;
    
    await logCallHistory({
      username: username,
      clientName: 'Desconocido',
      phone: To,
      type: 'call',
      status: CallStatus === 'completed' && duration > 0 ? 'answered' 
             : CallStatus === 'completed' && duration === 0 ? 'no-answer'
             : CallStatus === 'busy' ? 'busy'
             : CallStatus === 'failed' ? 'failed'
             : 'rejected',
      duration: duration,
      cost: 2,
      provider: 'twilio'
    });
    
    if (CallStatus === 'completed') {
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            success: 1,
            callAnswered: duration > 0 ? 1 : 0,
            callNoAnswer: duration === 0 ? 1 : 0,
            pending: -1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    } else if (CallStatus === 'busy') {
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            errors: 1,
            callBusy: 1,
            pending: -1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    } else if (CallStatus === 'failed' || CallStatus === 'no-answer' || CallStatus === 'canceled') {
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            errors: 1,
            callRejected: 1,
            pending: -1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    }
    
    res.sendStatus(200);
  } catch (error) {
    console.error('Error en call-status:', error);
    res.sendStatus(500);
  }
});

app.post('/api/sms-status', async (req, res) => {
  try {
    const { MessageStatus, MessageSid, To, ErrorCode } = req.body;
    const username = req.query.username;
    
    console.log(`SMS ${MessageSid} a ${To}: ${MessageStatus} - Usuario: ${username}${ErrorCode ? ` (Error: ${ErrorCode})` : ''}`);
    
    if (!username) {
      console.error('Username no proporcionado en webhook');
      return res.sendStatus(200);
    }
    
    await logCallHistory({
      username: username,
      clientName: 'Desconocido',
      phone: To,
      type: 'sms',
      status: MessageStatus === 'delivered' ? 'delivered' 
             : MessageStatus === 'sent' ? 'sent'
             : 'undelivered',
      cost: 1,
      provider: 'twilio'
    });
    
    if (MessageStatus === 'delivered') {
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            success: 1,
            pending: -1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    } else if (MessageStatus === 'failed' || MessageStatus === 'undelivered') {
      await Stats.updateOne(
        { username },
        { 
          $inc: { 
            errors: 1,
            pending: -1
          },
          lastUpdated: new Date()
        },
        { upsert: true }
      );
    }
    
    res.sendStatus(200);
  } catch (error) {
    console.error('Error en sms-status:', error);
    res.sendStatus(500);
  }
});

// SCHEDULER
cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const campaigns = await ScheduledCampaign.find({
      status: 'scheduled',
      scheduledDate: { $lte: now }
    }).populate('templateId').populate('clients');
    
    for (const campaign of campaigns) {
      console.log(`Ejecutando campaña: ${campaign.name} con ${campaign.provider}`);
      
      campaign.status = 'running';
      await campaign.save();
      
      const template = campaign.templateId;
      let success = 0;
      let errors = 0;
      
      for (const clientDoc of campaign.clients) {
        try {
          const message = replaceVariables(
            campaign.type === 'sms' ? template.smsMessage : template.callScript,
            {
              Nombre: clientDoc.name,
              Telefono: clientDoc.phone,
              Deuda: clientDoc.debt,
              Compañia: clientDoc.company
            }
          );
          
          if (campaign.provider === 'broadcaster') {
            if (campaign.type === 'sms') {
              await sendBroadcasterSMS(clientDoc.cleanPhone, message);
            } else {
              await sendBroadcasterCall(clientDoc.cleanPhone, message);
            }
          } else {
            if (!twilioClient) {
              throw new Error('Twilio no configurado');
            }
            
            if (campaign.type === 'sms') {
              await twilioClient.messages.create({
                body: message,
                from: TWILIO_PHONE_SMS,
                to: clientDoc.cleanPhone,
                statusCallback: `${BASE_URL}/api/sms-status?username=${encodeURIComponent(campaign.username)}`
              });
            } else {
              const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Mia" language="es-MX">${message}</Say>
</Response>`;
              await twilioClient.calls.create({
                twiml: twiml,
                from: TWILIO_PHONE_CALL,
                to: clientDoc.cleanPhone,
                statusCallback: `${BASE_URL}/api/call-status?username=${encodeURIComponent(campaign.username)}`,
                statusCallbackEvent: ['completed']
              });
            }
          }
          
          success++;
          
          clientDoc.lastContact = new Date();
          clientDoc.status = 'contacted';
          await clientDoc.save();
          
        } catch (error) {
          errors++;
          console.error(`Error con cliente ${clientDoc.name}:`, error);
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      campaign.status = 'completed';
      campaign.executedAt = new Date();
      campaign.results.success = success;
      campaign.results.errors = errors;
      await campaign.save();
      
      await Stats.findOneAndUpdate(
        { username: campaign.username },
        {
          $inc: {
            total: campaign.clients.length,
            success: success,
            errors: errors
          }
        }
      );
      
      await ActivityLog.create({
        username: campaign.username,
        message: `Campaña "${campaign.name}" completada con ${campaign.provider}: ${success} exitosos, ${errors} errores`,
        type: 'success'
      });
      
      console.log(`Campaña ${campaign.name} completada`);
    }
  } catch (error) {
    console.error('Error en scheduler:', error);
  }
});

function replaceVariables(text, client) {
  return text
    .replace(/\{Nombre\}/g, client.Nombre || client.name)
    .replace(/\{Telefono\}/g, client.Telefono || client.phone)
    .replace(/\{Deuda\}/g, client.Deuda || client.debt)
    .replace(/\{Compañia\}/g, client.Compañia || client.company);
}

async function logCallHistory(data) {
  try {
    await CallHistory.create({
      username: data.username,
      clientId: data.clientId,
      clientName: data.clientName,
      phone: data.phone,
      type: data.type,
      status: data.status,
      duration: data.duration || 0,
      cost: data.cost || 0,
      provider: data.provider,
      campaignId: data.campaignId
    });
  } catch (error) {
    console.error('Error logging call history:', error);
  }
}

// Endpoint para verificar IP publica
app.get('/api/check-ip', async (req, res) => {
  try {
    const ipifyResponse = await axios.get('https://api.ipify.org?format=json', axiosConfig);
    res.json({ 
      render_outbound_ip: ipifyResponse.data.ip,
      request_ip: req.ip,
      x_forwarded_for: req.headers['x-forwarded-for'],
      x_real_ip: req.headers['x-real-ip'],
      timestamp: new Date().toISOString(),
      nota: 'La IP render_outbound_ip es la que debes enviar a Broadcaster',
      proxy_enabled: PROXY_URL ? true : false,
      proxy_info: PROXY_URL ? 'IP estática activa' : 'IP dinámica de Render'
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});

// RUTAS FRONTEND
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/test', (req, res) => {
  res.json({ 
    status: 'OK',
    message: 'Servidor hibrido Twilio + Broadcaster funcionando',
    database: mongoose.connection.readyState === 1 ? 'Conectada' : 'Desconectada',
    scheduler: 'Activo',
    providers: {
      twilio: twilioClient ? 'Configurado' : 'No configurado',
      broadcaster: 'Configurado'
    }
  });
});

// MIDDLEWARE PARA VERIFICAR ADMIN
async function isAdmin(req, res, next) {
  try {
    const { username } = req.body;
    if (!username) {
      return res.status(401).json({ success: false, error: 'Usuario no autenticado' });
    }
    
    const user = await User.findOne({ username });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Acceso denegado. Solo administradores.' });
    }
    
    req.adminUser = user;
    next();
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
}

// ENDPOINTS DE ADMINISTRADOR
app.post('/api/admin/users', isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password')
      .sort({ createdAt: -1 });
    
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/users/:username/credits', isAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { amount, description } = req.body;
    const adminUsername = req.adminUser.username;
    
    if (!amount || amount === 0) {
      return res.status(400).json({ success: false, error: 'Cantidad inválida' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
    }
    
    const balanceBefore = user.credits;
    const balanceAfter = balanceBefore + amount;
    
    if (balanceAfter < 0) {
      return res.status(400).json({ success: false, error: 'Saldo insuficiente' });
    }
    
    user.credits = balanceAfter;
    await user.save();
    
    await Transaction.create({
      username: username,
      type: amount > 0 ? 'add' : 'deduct',
      amount: Math.abs(amount),
      balanceBefore,
      balanceAfter,
      description: description || (amount > 0 ? 'Créditos agregados por admin' : 'Créditos deducidos por admin'),
      adminUser: adminUsername
    });
    
    await ActivityLog.create({
      username: adminUsername,
      message: `${amount > 0 ? 'Agregó' : 'Dedujo'} ${Math.abs(amount)} créditos ${amount > 0 ? 'a' : 'de'} ${username}`,
      type: 'info'
    });
    
    res.json({ 
      success: true, 
      newBalance: balanceAfter,
      message: `Se ${amount > 0 ? 'agregaron' : 'dedujeron'} ${Math.abs(amount)} créditos exitosamente`
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/transactions', isAdmin, async (req, res) => {
  try {
    const { filterUsername, limit = 100 } = req.body;
    
    const query = filterUsername ? { username: filterUsername } : {};
    
    const transactions = await Transaction.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    res.json({ success: true, transactions });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/transactions/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const transactions = await Transaction.find({ username })
      .sort({ timestamp: -1 })
      .limit(50);
    
    res.json({ success: true, transactions });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/users/:username/delete', isAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const adminUsername = req.adminUser.username;
    
    if (username === adminUsername) {
      return res.status(400).json({ success: false, error: 'No puedes eliminar tu propia cuenta' });
    }
    
    if (username === 'admin') {
      return res.status(400).json({ success: false, error: 'No se puede eliminar la cuenta admin principal' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
    }
    
    await User.deleteOne({ username });
    await Template.deleteMany({ username });
    await Client.deleteMany({ username });
    await ScheduledCampaign.deleteMany({ username });
    await Stats.deleteOne({ username });
    await ActivityLog.deleteMany({ username });
    await Transaction.deleteMany({ username });
    
    await ActivityLog.create({
      username: adminUsername,
      message: `Eliminó la cuenta de usuario: ${username}`,
      type: 'info'
    });
    
    res.json({ success: true, message: 'Usuario eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/users/:username/role', isAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { role } = req.body;
    const adminUsername = req.adminUser.username;
    
    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ success: false, error: 'Rol inválido' });
    }
    
    if (username === 'admin') {
      return res.status(400).json({ success: false, error: 'No se puede cambiar el rol del admin principal' });
    }
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
    }
    
    user.role = role;
    await user.save();
    
    await ActivityLog.create({
      username: adminUsername,
      message: `Cambió el rol de ${username} a ${role}`,
      type: 'info'
    });
    
    res.json({ success: true, message: `Rol actualizado a ${role}` });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ENDPOINT DE ESTADÍSTICAS GLOBALES (ADMIN)
app.post('/api/admin/global-stats', isAdmin, async (req, res) => {
  try {
    console.log('📊 Obteniendo estadísticas globales...');
    
    const users = await User.find({}, 'username credits');
    console.log(`✅ ${users.length} usuarios encontrados`);
    
    const allStats = await Stats.find({});
    console.log(`✅ ${allStats.length} estadísticas encontradas`);
    
    let totalMessages = 0;
    let totalCalls = 0;
    let totalSuccess = 0;
    let totalErrors = 0;
    let totalPending = 0;
    
    const userActivity = {
      labels: [],
      values: []
    };
    
    const creditsUsage = {
      labels: [],
      values: []
    };
    
    for (const user of users) {
      const stats = allStats.find(s => s.username === user.username);
      if (stats) {
        const userTotal = stats.total || 0;
        totalMessages += (stats.success || 0);
        totalCalls += (stats.callAnswered || 0) + (stats.callBusy || 0) + (stats.callNoAnswer || 0) + (stats.callRejected || 0);
        totalSuccess += stats.success || 0;
        totalErrors += stats.errors || 0;
        totalPending += stats.pending || 0;
        
        if (userTotal > 0) {
          userActivity.labels.push(user.username);
          userActivity.values.push(userTotal);
        }
      }
      
      creditsUsage.labels.push(user.username);
      creditsUsage.values.push(user.credits || 0);
    }
    
    console.log(`📈 Total mensajes: ${totalMessages}, Total llamadas: ${totalCalls}`);
    
    const totalCampaigns = await ScheduledCampaign.countDocuments();
    console.log(`📋 Total campañas: ${totalCampaigns}`);
    
    const successRate = (totalSuccess + totalErrors) > 0 
      ? Math.round((totalSuccess / (totalSuccess + totalErrors)) * 100) + '%'
      : '0%';
    
    const messageStatus = {
      success: totalSuccess,
      errors: totalErrors,
      pending: totalPending
    };
    
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentHistory = await CallHistory.find({
      timestamp: { $gte: sevenDaysAgo }
    });
    
    const dailyData = Array(7).fill(null).map(() => ({ messages: 0, calls: 0 }));
    
    recentHistory.forEach(record => {
      const daysAgo = Math.floor((Date.now() - new Date(record.timestamp).getTime()) / (1000 * 60 * 60 * 24));
      if (daysAgo >= 0 && daysAgo < 7) {
        const index = 6 - daysAgo;
        if (record.type === 'sms') {
          dailyData[index].messages++;
        } else if (record.type === 'call') {
          dailyData[index].calls++;
        }
      }
    });
    
    const weeklyActivity = {
      messages: dailyData.map(d => d.messages),
      calls: dailyData.map(d => d.calls)
    };
    
    const response = {
      success: true,
      stats: {
        totalCampaigns,
        totalMessages,
        totalCalls,
        successRate,
        userActivity,
        messageStatus,
        creditsUsage,
        weeklyActivity
      }
    };
    
    console.log('✅ Estadísticas calculadas exitosamente');
    
    res.json(response);
  } catch (error) {
    console.error('❌ Error obteniendo estadísticas:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ESTADÍSTICAS AVANZADAS
app.get('/api/call-history/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { limit = 50, type, status } = req.query;
    
    let query = { username };
    if (type) query.type = type;
    if (status) query.status = status;
    
    const history = await CallHistory.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .lean();
    
    res.json({ success: true, history });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/stats-advanced/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const basicStats = await Stats.findOne({ username });
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const weeklyHistory = await CallHistory.find({ username, timestamp: { $gte: sevenDaysAgo } });
    const dailyStats = {};
    weeklyHistory.forEach(call => {
      const day = call.timestamp.toISOString().split('T')[0];
      if (!dailyStats[day]) dailyStats[day] = { total: 0, success: 0, failed: 0, sms: 0, calls: 0 };
      dailyStats[day].total++;
      if (call.type === 'sms') dailyStats[day].sms++;
      if (call.type === 'call') dailyStats[day].calls++;
      if (['answered', 'completed', 'delivered'].includes(call.status)) {
        dailyStats[day].success++;
      } else {
        dailyStats[day].failed++;
      }
    });
    const hourlyStats = Array(24).fill(null).map(() => ({ total: 0, success: 0 }));
    weeklyHistory.forEach(call => {
      const hour = call.timestamp.getHours();
      hourlyStats[hour].total++;
      if (['answered', 'completed', 'delivered'].includes(call.status)) hourlyStats[hour].success++;
    });
    let bestHour = { hour: 10, successRate: 0 };
    hourlyStats.forEach((stat, hour) => {
      if (stat.total > 0) {
        const rate = (stat.success / stat.total) * 100;
        if (rate > bestHour.successRate) bestHour = { hour, successRate: rate };
      }
    });
    const smsStats = weeklyHistory.filter(h => h.type === 'sms');
    const callStats = weeklyHistory.filter(h => h.type === 'call');
    const comparison = {
      sms: {
        total: smsStats.length,
        success: smsStats.filter(s => ['delivered', 'completed'].includes(s.status)).length,
        successRate: smsStats.length > 0 ? ((smsStats.filter(s => ['delivered', 'completed'].includes(s.status)).length / smsStats.length) * 100).toFixed(2) : 0
      },
      calls: {
        total: callStats.length,
        success: callStats.filter(c => c.status === 'answered').length,
        successRate: callStats.length > 0 ? ((callStats.filter(c => c.status === 'answered').length / callStats.length) * 100).toFixed(2) : 0
      }
    };
    res.json({
      success: true,
      stats: { basic: basicStats || { total: 0, success: 0, errors: 0, pending: 0, callAnswered: 0, callRejected: 0, callBusy: 0, callNoAnswer: 0 }, daily: dailyStats, hourly: hourlyStats, bestHour, comparison, weeklyTotal: weeklyHistory.length }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/call-history', async (req, res) => {
  try {
    const { username, clientId, clientName, phone, type, status, duration, cost, provider, campaignId } = req.body;
    const history = await CallHistory.create({ username, clientId, clientName, phone, type, status, duration: duration || 0, cost: cost || 0, provider, campaignId });
    res.json({ success: true, history });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// INICIAR SERVIDOR
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log('========================================');
  console.log('🚀 SERVIDOR HIBRIDO TWILIO + BROADCASTER');
  console.log('========================================');
  console.log(`📍 URL: ${BASE_URL}`);
  console.log(`💾 MongoDB: ${mongoose.connection.readyState === 1 ? 'Conectada ✅' : 'Conectando... ⏳'}`);
  console.log(`⏰ Scheduler: Activo (revisa cada minuto)`);
  console.log(`🔌 Puerto: ${PORT}`);
  console.log(`📞 Twilio: ${twilioClient ? 'Configurado ✅' : 'No configurado ⚠️'}`);
  console.log(`📡 Broadcaster: Configurado ✅`);
  console.log(`🔒 Proxy: ${PROXY_URL ? 'IP Estática Activa ✅' : 'IP Dinámica ⚠️'}`);
  console.log('========================================\n');
});