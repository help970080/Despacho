const express = require('express');
const mongoose = require('mongoose');
const twilio = require('twilio');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===================================
// 🗄️ CONEXIÓN A MONGODB
// ===================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cobranza-system')
.then(() => console.log('✅ Conectado a MongoDB'))
.catch(err => console.error('❌ Error conectando a MongoDB:', err));

// ===================================
// 📊 MODELOS DE MONGODB
// ===================================

// Usuario
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

// Plantilla
const templateSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  company: { type: String, required: true },
  name: { type: String, required: true },
  smsMessage: String,
  callScript: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
});

// Cliente
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

// Campaña Programada
const scheduledCampaignSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  name: { type: String, required: true },
  templateId: { type: mongoose.Schema.Types.ObjectId, ref: 'Template' },
  type: { type: String, enum: ['sms', 'call'], required: true },
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

// Estadísticas
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

// Log de Actividad
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

// ===================================
// 🔐 CREAR USUARIO ADMIN INICIAL
// ===================================
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
      console.log('✅ Usuario admin creado: admin / admin123');
    }
  } catch (error) {
    console.error('Error creando admin:', error);
  }
}
createAdminUser();

// ===================================
// ⚙️ CONFIGURACIÓN TWILIO
// ===================================
const ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_SMS = process.env.TWILIO_PHONE_SMS;
const TWILIO_PHONE_CALL = process.env.TWILIO_PHONE_CALL;
const BASE_URL = process.env.RENDER_EXTERNAL_URL || process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

if (!ACCOUNT_SID || !AUTH_TOKEN || !TWILIO_PHONE_SMS || !TWILIO_PHONE_CALL) {
  console.error('❌ ERROR: Faltan variables de entorno de Twilio');
  console.log('Variables recibidas:');
  console.log('ACCOUNT_SID:', ACCOUNT_SID ? 'Definido' : 'No definido');
  console.log('AUTH_TOKEN:', AUTH_TOKEN ? 'Definido' : 'No definido');
  console.log('TWILIO_PHONE_SMS:', TWILIO_PHONE_SMS ? 'Definido' : 'No definido');
  console.log('TWILIO_PHONE_CALL:', TWILIO_PHONE_CALL ? 'Definido' : 'No definido');
}

const client = twilio(ACCOUNT_SID, AUTH_TOKEN);

// ===================================
// 🔐 ENDPOINTS DE AUTENTICACIÓN
// ===================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Credenciales inválidas' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, error: 'Credenciales inválidas' });
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

// ===================================
// 👥 ENDPOINTS DE USUARIOS
// ===================================
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
    
    // Crear estadísticas iniciales
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
    await Stats.deleteOne({ username });
    await ActivityLog.deleteMany({ username });
    await ScheduledCampaign.deleteMany({ username });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===================================
// 📄 ENDPOINTS DE PLANTILLAS
// ===================================
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
    const template = await Template.create(req.body);
    res.json({ success: true, template });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/templates/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const template = await Template.findByIdAndUpdate(
      id,
      { ...req.body, updatedAt: new Date() },
      { new: true }
    );
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

// ===================================
// 👤 ENDPOINTS DE CLIENTES
// ===================================
app.get('/api/clients/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const clients = await Client.find({ username }).sort({ createdAt: -1 });
    res.json({ success: true, clients });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/clients', async (req, res) => {
  try {
    const client = await Client.create(req.body);
    res.json({ success: true, client });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/clients/bulk', async (req, res) => {
  try {
    const { username, clients } = req.body;
    
    if (!clients || clients.length === 0) {
      return res.status(400).json({ success: false, error: 'No se proporcionaron clientes' });
    }
    
    const clientsToInsert = clients.map(c => ({
      username,
      name: c.name || c.Nombre || '',
      phone: c.phone || c.Telefono || '',
      cleanPhone: c.cleanPhone || c.phone || c.Telefono || '',
      debt: c.debt || c.Deuda || '0',
      company: c.company || c.Compañia || '',
      status: 'pending'
    }));
    
    const insertedClients = await Client.insertMany(clientsToInsert);
    
    // Crear log de actividad
    await ActivityLog.create({
      username,
      message: `${insertedClients.length} clientes cargados`,
      type: 'success'
    });
    
    res.json({ success: true, count: insertedClients.length, clients: insertedClients });
  } catch (error) {
    console.error('Error en /api/clients/bulk:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/clients/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const client = await Client.findByIdAndUpdate(id, req.body, { new: true });
    res.json({ success: true, client });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/clients/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await Client.findByIdAndDelete(id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/clients/user/:username', async (req, res) => {
  try {
    const { username } = req.params;
    await Client.deleteMany({ username });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===================================
// 📅 ENDPOINTS DE CAMPAÑAS PROGRAMADAS
// ===================================
app.get('/api/scheduled-campaigns/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const campaigns = await ScheduledCampaign.find({ username })
      .populate('templateId')
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
    const { username, name, templateId, type, scheduledDate, clientIds } = req.body;
    
    const campaign = await ScheduledCampaign.create({
      username,
      name,
      templateId,
      type,
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

// ===================================
// 📊 ENDPOINTS DE ESTADÍSTICAS
// ===================================
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

// ===================================
// 📋 ENDPOINTS DE LOGS
// ===================================
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

// ===================================
// 📱 ENDPOINTS TWILIO
// ===================================
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message, username } = req.body;
    
    const result = await client.messages.create({
      body: message,
      from: TWILIO_PHONE_SMS,
      to: to
    });
    
    // Descontar créditos
    await User.findOneAndUpdate(
      { username },
      { $inc: { credits: -1 } }
    );
    
    res.json({ success: true, sid: result.sid, status: result.status });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/make-call', async (req, res) => {
  try {
    const { to, script, username } = req.body;
    
    const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Mia" language="es-MX">${script}</Say>
  <Pause length="1"/>
  <Say voice="Polly.Mia" language="es-MX">Para más información, comuníquese con nosotros. Gracias.</Say>
</Response>`;
    
    const result = await client.calls.create({
      twiml: twiml,
      from: TWILIO_PHONE_CALL,
      to: to,
      statusCallback: `${BASE_URL}/api/call-status`,
      statusCallbackEvent: ['completed']
    });
    
    // Descontar créditos
    await User.findOneAndUpdate(
      { username },
      { $inc: { credits: -2 } }
    );
    
    res.json({ success: true, sid: result.sid, status: result.status });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/call-status', async (req, res) => {
  const { CallStatus } = req.body;
  console.log(`📊 Estado de llamada: ${CallStatus}`);
  res.sendStatus(200);
});

// ===================================
// ⏰ SCHEDULER - EJECUTAR CAMPAÑAS PROGRAMADAS
// ===================================
cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const campaigns = await ScheduledCampaign.find({
      status: 'scheduled',
      scheduledDate: { $lte: now }
    }).populate('templateId').populate('clients');
    
    for (const campaign of campaigns) {
      console.log(`🚀 Ejecutando campaña: ${campaign.name}`);
      
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
          
          if (campaign.type === 'sms') {
            await client.messages.create({
              body: message,
              from: TWILIO_PHONE_SMS,
              to: clientDoc.cleanPhone
            });
          } else {
            const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Mia" language="es-MX">${message}</Say>
</Response>`;
            await client.calls.create({
              twiml: twiml,
              from: TWILIO_PHONE_CALL,
              to: clientDoc.cleanPhone
            });
          }
          
          success++;
          
          // Actualizar cliente
          clientDoc.lastContact = new Date();
          clientDoc.status = 'contacted';
          await clientDoc.save();
          
        } catch (error) {
          errors++;
          console.error(`Error con cliente ${clientDoc.name}:`, error);
        }
        
        // Delay entre envíos
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // Actualizar resultados
      campaign.status = 'completed';
      campaign.executedAt = new Date();
      campaign.results.success = success;
      campaign.results.errors = errors;
      await campaign.save();
      
      // Actualizar estadísticas
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
      
      // Log
      await ActivityLog.create({
        username: campaign.username,
        message: `Campaña "${campaign.name}" completada: ${success} exitosos, ${errors} errores`,
        type: 'success'
      });
      
      console.log(`✅ Campaña ${campaign.name} completada`);
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

// ===================================
// 🏠 RUTAS FRONTEND
// ===================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/test', (req, res) => {
  res.json({ 
    status: 'OK',
    message: '🚀 Servidor con MongoDB funcionando',
    database: mongoose.connection.readyState === 1 ? 'Conectada' : 'Desconectada',
    scheduler: 'Activo',
    mongodbUri: process.env.MONGODB_URI ? 'Configurada' : 'No configurada'
  });
});

// ===================================
// 🌐 INICIAR SERVIDOR
// ===================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('🚀 SERVIDOR CON MONGODB Y SCHEDULER INICIADO');
  console.log('╚══════════════════════════════════════════════╝');
  console.log(`🔗 URL: ${BASE_URL}`);
  console.log(`📊 MongoDB: ${mongoose.connection.readyState === 1 ? '✅ Conectada' : '⏳ Conectando...'}`);
  console.log(`⏰ Scheduler: ✅ Activo (revisa cada minuto)`);
  console.log(`🌐 Puerto: ${PORT}`);
  console.log('═══════════════════════════════════════════════\n');
});
