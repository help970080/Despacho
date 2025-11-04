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
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error conectando a MongoDB:', err));

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

const User = mongoose.model('User', userSchema);
const Template = mongoose.model('Template', templateSchema);
const Client = mongoose.model('Client', clientSchema);
const ScheduledCampaign = mongoose.model('ScheduledCampaign', scheduledCampaignSchema);
const Stats = mongoose.model('Stats', statsSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// CREAR USUARIO ADMIN INICIAL
async function createAdminUser() {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        name: 'SuperAdministrador',
        email: 'admin@sistema.com',
        credits: 10000,
        role: 'admin'
      });
      console.log('Usuario admin creado: admin / admin123');
    }
  } catch (error) {
    console.error('Error creando admin:', error);
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
  console.log('Twilio configurado');
} else {
  console.log('Twilio no configurado (variables de entorno faltantes)');
}

// CONFIGURACION BROADCASTER
const BROADCASTER_API_KEY = process.env.BROADCASTER_API_KEY || '5031';
const BROADCASTER_AUTHORIZATION = process.env.BROADCASTER_AUTHORIZATION || 'qNYY7U54Bb3rsG0VZu8on7bzE+w=';
const BROADCASTER_SMS_URL = 'https://api.broadcastermobile.com/brdcstr-endpoint-web/services/messaging/';
const BROADCASTER_VOICE_URL = 'https://api.broadcastermobile.com/broadcaster-voice-api/services/voice/sendCall';

console.log('Broadcaster configurado');

// CONFIGURACION PROXY ESTATICO (QuotaGuard o Fixie)
const PROXY_URL = process.env.QUOTAGUARDSTATIC_URL || process.env.FIXIE_URL || null;

// Configuración de axios para usar proxy HTTPS correctamente
let axiosConfig = {};

if (PROXY_URL) {
  const proxyUrl = new URL(PROXY_URL);
  console.log(`✅ Proxy estático configurado: ${proxyUrl.hostname}:${proxyUrl.port || 80}`);
  
  // Crear agente HTTPS que soporte proxy HTTP
  const httpsAgent = new HttpsProxyAgent(PROXY_URL);
  
  axiosConfig = {
    httpsAgent: httpsAgent,
    proxy: false  // Desactivar proxy por defecto de axios
  };
  
  console.log('🔒 Todas las peticiones salientes usarán IP estática del proxy');
} else {
  console.log('⚠️  Proxy NO configurado - usando IP dinámica de Render');
  console.log('   Para IP estática, agrega QUOTAGUARDSTATIC_URL o FIXIE_URL a variables de entorno');
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
    // Verificar IP publica
    try {
      const ipCheck = await axios.get('https://api.ipify.org?format=json', axiosConfig);
      console.log('===========================================');
      console.log('MI IP PUBLICA (SALIDA A INTERNET):', ipCheck.data.ip);
      console.log('===========================================');
      console.log(PROXY_URL ? '🔒 Usando IP estática del proxy' : '⚠️  Usando IP dinámica de Render');
    } catch (e) {
      console.log('No se pudo obtener IP:', e.message);
    }

    let cleanNumber = phoneNumber.replace(/\D/g, '');
    if (cleanNumber.startsWith('52')) {
      cleanNumber = cleanNumber.substring(2);
    }
    if (cleanNumber.length !== 10) {
      throw new Error('Numero debe tener 10 digitos');
    }

    console.log('📤 Enviando SMS a:', `52${cleanNumber}`);

    // FORMATO SEGÚN CONFIGURACIÓN OFICIAL DE BROADCASTER
    const requestBody = {
      apiKey: parseInt(BROADCASTER_API_KEY),
      country: 'MX',  // MAYÚSCULAS según Broadcaster
      dial: 41414,  // Número sin comillas
      message: message,
      msisdns: [parseInt(`52${cleanNumber}`)],  // Número en array
      tag: 'sistema-cobranza'
    };

    console.log('📋 Request Body:', JSON.stringify(requestBody, null, 2));

    const response = await axios.post(BROADCASTER_SMS_URL, requestBody, {
      ...axiosConfig,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': BROADCASTER_AUTHORIZATION
      }
    });

    console.log('✅ Respuesta de Broadcaster:', response.status, response.data);
    return { success: true, data: response.data };
  } catch (error) {
    console.error('❌ Error enviando SMS con Broadcaster:');
    console.error('   Status:', error.response?.status);
    console.error('   Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('   Message:', error.message);
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

    console.log('📞 Haciendo llamada a:', `52${cleanNumber}`);

    // FORMATO SEGÚN CONFIGURACIÓN OFICIAL DE BROADCASTER
    const requestBody = {
      phoneNumber: `52${cleanNumber}`,  // String con 52 + 10 dígitos
      country: 'MX',
      message: {
        text: message,
        volume: 0,
        emphasis: 0,
        speed: 0,
        voice: 'Mia'
      }
    };

    console.log('📋 Voice Request Body:', JSON.stringify(requestBody, null, 2));

    const response = await axios.post(BROADCASTER_VOICE_URL, requestBody, {
      ...axiosConfig,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': BROADCASTER_AUTHORIZATION
      }
    });

    console.log('✅ Respuesta de Broadcaster Voice:', response.status, response.data);
    return { success: true, data: response.data };
  } catch (error) {
    console.error('❌ Error enviando llamada con Broadcaster:');
    console.error('   Status:', error.response?.status);
    console.error('   Data:', JSON.stringify(error.response?.data, null, 2));
    console.error('   Message:', error.message);
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

// SCHEDULER - EJECUTAR CAMPAÑAS PROGRAMADAS
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

// INICIAR SERVIDOR
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('========================================');
  console.log('SERVIDOR HIBRIDO TWILIO + BROADCASTER');
  console.log('========================================');
  console.log(`URL: ${BASE_URL}`);
  console.log(`MongoDB: ${mongoose.connection.readyState === 1 ? 'Conectada' : 'Conectando...'}`);
  console.log(`Scheduler: Activo (revisa cada minuto)`);
  console.log(`Puerto: ${PORT}`);
  console.log(`Twilio: ${twilioClient ? 'Configurado' : 'No configurado'}`);
  console.log(`Broadcaster: Configurado`);
  console.log('========================================\n');
});