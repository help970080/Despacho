// ================================
// SERVIDOR DE COBRANZA + WHATSAPP MASIVO (CORREGIDO PARA RENDER)
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
const twilio = require('twilio');

// IMPORTANTE: Deshabilitamos WhatsApp-Web.js en Render porque no funciona con Puppeteer
// const { Client: WhatsAppClient, LocalAuth } = require('whatsapp-web.js');

// ================================
// CONFIGURACIÓN DE ENTORNO
// ================================
const isRender = process.env.RENDER === 'true' || process.env.RENDER_EXTERNAL_URL;

// ================================
// APP
// ================================
const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;

// ================================
// MONGODB (CON RECONEXIÓN)
// ================================
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI;

if (!MONGODB_URI) {
  console.warn('⚠️  ADVERTENCIA: MONGODB_URI no está definida. Usando base de datos en memoria.');
} else {
  mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log('💾 MongoDB conectado exitosamente'))
  .catch(err => {
    console.error('❌ Error de conexión a MongoDB:', err.message);
    console.log('🔄 Continuando sin base de datos...');
  });
}

// ================================
// SCHEMAS / MODELOS (CON FALLBACK EN MEMORIA)
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

// Colección en memoria como fallback
const memoryDB = {
  users: [],
  clients: [],
  campaigns: []
};

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Client = mongoose.models.Client || mongoose.model('Client', clientSchema);
const Campaign = mongoose.models.Campaign || mongoose.model('Campaign', campaignSchema);

// Helper para usar DB real o memoria
const db = {
  async findUser(query) {
    if (mongoose.connection.readyState === 1) {
      return await User.findOne(query);
    }
    return memoryDB.users.find(u => u.username === query.username);
  },
  
  async saveUser(user) {
    if (mongoose.connection.readyState === 1) {
      return await user.save();
    }
    const index = memoryDB.users.findIndex(u => u.username === user.username);
    if (index >= 0) {
      memoryDB.users[index] = user;
    } else {
      memoryDB.users.push(user);
    }
    return user;
  }
};

// ================================
// TWILIO (PARA WHATSAPP BUSINESS API)
// ================================
let twilioClient = null;
if (process.env.TWILIO_SID && process.env.TWILIO_TOKEN) {
  twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
  console.log('📞 Twilio configurado para WhatsApp Business API');
} else {
  console.warn('⚠️  Twilio no configurado. WhatsApp Business API no disponible.');
}

// ================================
// WHATSAPP - SOLO TWILIO API (NO WHATSAPP-WEB.JS)
// ================================
console.log('📱 Usando Twilio WhatsApp Business API (whatsapp-web.js deshabilitado en Render)');

// ================================
// ENDPOINTS PRINCIPALES
// ================================

app.get('/', (req, res) => {
  res.json({
    status: '🚀 Sistema de Cobranza activo',
    environment: isRender ? 'Render' : 'Local',
    features: {
      whatsapp: 'Twilio Business API',
      database: mongoose.connection.readyState === 1 ? 'MongoDB' : 'Memoria',
      cron: 'Activo'
    }
  });
});

// Health check para Render
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }
  
  try {
    const user = await db.findUser({ username });
    
    // Usuario demo si no existe
    if (!user) {
      if (username === 'admin' && password === 'admin123') {
        return res.json({ 
          success: true, 
          user: { username: 'admin', credits: 100 },
          demo: true 
        });
      }
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }
    
    // Verificar contraseña (en producción usar bcrypt)
    const ok = user.password === password || await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    
    res.json({ success: true, user: { username: user.username, credits: user.credits } });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Enviar WhatsApp usando Twilio API
app.post('/send-whatsapp', async (req, res) => {
  const { phone, message, username } = req.body;
  
  if (!phone || !message || !username) {
    return res.status(400).json({ error: 'Teléfono, mensaje y usuario requeridos' });
  }
  
  // Validar formato de teléfono
  const cleanPhone = phone.replace(/\D/g, '');
  if (cleanPhone.length < 10) {
    return res.status(400).json({ error: 'Número de teléfono inválido' });
  }
  
  try {
    // Verificar créditos del usuario
    const user = await db.findUser({ username });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    if (user.credits < 1) {
      return res.status(400).json({ error: 'Créditos insuficientes' });
    }
    
    // OPCIÓN 1: Usar Twilio WhatsApp Business API (RECOMENDADO)
    if (twilioClient && process.env.TWILIO_WHATSAPP_NUMBER) {
      const formattedPhone = `whatsapp:+${cleanPhone}`;
      const fromNumber = `whatsapp:${process.env.TWILIO_WHATSAPP_NUMBER}`;
      
      const twilioResponse = await twilioClient.messages.create({
        body: message,
        from: fromNumber,
        to: formattedPhone
      });
      
      console.log('✅ WhatsApp enviado via Twilio SID:', twilioResponse.sid);
      
      // Descontar crédito
      user.credits -= 1;
      await db.saveUser(user);
      
      return res.json({ 
        success: true, 
        method: 'twilio',
        messageId: twilioResponse.sid,
        creditsRemaining: user.credits
      });
    }
    
    // OPCIÓN 2: Simular envío (para desarrollo/demo)
    console.log(`📱 [SIMULACIÓN] WhatsApp a ${phone}: ${message.substring(0, 50)}...`);
    
    // Descontar crédito
    user.credits -= 1;
    await db.saveUser(user);
    
    // Simular delay de envío
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    res.json({ 
      success: true, 
      method: 'simulation',
      creditsRemaining: user.credits,
      note: 'Twilio no configurado. Mensaje simulado.'
    });
    
  } catch (error) {
    console.error('❌ Error enviando WhatsApp:', error);
    
    if (error.code === 21211) {
      return res.status(400).json({ error: 'Número de teléfono inválido' });
    }
    
    res.status(500).json({ 
      error: 'Error enviando WhatsApp', 
      details: isRender ? null : error.message 
    });
  }
});

// Endpoint para verificar créditos
app.get('/credits/:username', async (req, res) => {
  try {
    const user = await db.findUser({ username: req.params.username });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json({ credits: user.credits });
  } catch (error) {
    res.status(500).json({ error: 'Error obteniendo créditos' });
  }
});

// CRUD para clientes
app.get('/clients', async (req, res) => {
  try {
    let clients;
    if (mongoose.connection.readyState === 1) {
      clients = await Client.find({});
    } else {
      clients = memoryDB.clients;
    }
    res.json(clients);
  } catch (error) {
    res.status(500).json({ error: 'Error obteniendo clientes' });
  }
});

app.post('/clients', async (req, res) => {
  try {
    const { name, phone, debt } = req.body;
    
    if (mongoose.connection.readyState === 1) {
      const client = new Client({ name, phone, debt, status: 'pending' });
      await client.save();
      res.json(client);
    } else {
      const newClient = { 
        id: Date.now().toString(), 
        name, 
        phone, 
        debt, 
        status: 'pending' 
      };
      memoryDB.clients.push(newClient);
      res.json(newClient);
    }
  } catch (error) {
    res.status(500).json({ error: 'Error creando cliente' });
  }
});

// ================================
// TAREAS PROGRAMADAS (CRON)
// ================================
if (!isRender) {
  // En local, ejecutar cron normalmente
  cron.schedule('0 * * * *', () => {
    console.log('⏰ Tarea programada ejecutada:', new Date().toLocaleString());
  });
  console.log('⏰ Cron jobs activados (local)');
} else {
  // En Render, usar endpoints para tareas programadas
  console.log('⏰ Cron jobs desactivados en Render (usar Scheduler de Render)');
  
  // Endpoint para ejecutar tareas manualmente
  app.post('/run-cron', async (req, res) => {
    const { secret } = req.body;
    if (secret !== process.env.CRON_SECRET) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    
    console.log('🔧 Ejecutando tarea programada manualmente');
    // Aquí colocar la lógica de tus tareas programadas
    // Ej: enviar recordatorios, actualizar estados, etc.
    
    res.json({ success: true, executedAt: new Date().toISOString() });
  });
}

// ================================
// CONFIGURACIÓN PARA RENDER
// ================================
if (isRender) {
  // Crear usuario admin por defecto si no existe
  const createDefaultAdmin = async () => {
    try {
      const adminExists = await db.findUser({ username: 'admin' });
      if (!adminExists) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const adminUser = {
          username: 'admin',
          password: hashedPassword,
          credits: 100
        };
        await db.saveUser(adminUser);
        console.log('👑 Usuario admin creado por defecto');
      }
    } catch (error) {
      console.error('Error creando admin:', error);
    }
  };
  
  // Esperar a que la app esté lista
  setTimeout(createDefaultAdmin, 3000);
}

// ================================
// MANEJO DE ERRORES
// ================================
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err);
  res.status(500).json({ 
    error: 'Error interno del servidor',
    details: isRender ? null : err.message
  });
});

// ================================
// INICIAR SERVIDOR
// ================================
app.listen(PORT, () => {
  console.log('════════════════════════════════════════════════');
  console.log('🚀 SERVIDOR DE COBRANZA + WHATSAPP MASIVO');
  console.log(`🌐 Entorno: ${isRender ? 'Render' : 'Local'}`);
  console.log(`🔌 Puerto: ${PORT}`);
  console.log(`💾 MongoDB: ${mongoose.connection.readyState === 1 ? 'Conectado' : 'Desconectado/Memoria'}`);
  console.log(`📱 WhatsApp: ${twilioClient ? 'Twilio Business API' : 'Simulación'}`);
  console.log('════════════════════════════════════════════════');
});