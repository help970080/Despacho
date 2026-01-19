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
const twilio = require('twilio');

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
// MONGODB CONEXIÓN MEJORADA
// ================================
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.warn('⚠️  ADVERTENCIA: MONGODB_URI no está definida. Usando base de datos en memoria.');
} else {
  // Extraer nombre de base de datos si no está en la URI
  let connectionString = MONGODB_URI;
  if (!MONGODB_URI.includes('/?') && !MONGODB_URI.match(/\/[^/?]+(\?|$)/)) {
    connectionString = MONGODB_URI.replace(/\?/, '/cobranza?');
  }
  
  mongoose.connect(connectionString, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
  })
  .then(() => console.log('💾 MongoDB conectado exitosamente'))
  .catch(err => {
    console.error('❌ Error de conexión a MongoDB:', err.message);
    console.log('🔄 Continuando sin base de datos...');
  });
}

// ================================
// SCHEMAS / MODELOS
// ================================

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  credits: { type: Number, default: 100 }
});

const clientSchema = new mongoose.Schema({
  name: String,
  phone: String,
  debt: Number,
  status: { type: String, default: 'pending' }
});

const campaignSchema = new mongoose.Schema({
  user: String,
  message: String,
  total: Number,
  sent: Number,
  errorsCount: Number,
  createdAt: { type: Date, default: Date.now }
});

// Modelos
const User = mongoose.models.User || mongoose.model('User', userSchema);
const Client = mongoose.models.Client || mongoose.model('Client', clientSchema);
const Campaign = mongoose.models.Campaign || mongoose.model('Campaign', campaignSchema);

// Colección en memoria como fallback
const memoryDB = {
  users: [],
  clients: [],
  campaigns: []
};

// Helper para usar DB real o memoria - CORREGIDO
const db = {
  async findUser(query) {
    try {
      if (mongoose.connection.readyState === 1) {
        return await User.findOne(query);
      }
      return memoryDB.users.find(u => u.username === query.username);
    } catch (error) {
      console.error('Error en findUser:', error);
      return null;
    }
  },
  
  async saveUser(userData) {
    try {
      if (mongoose.connection.readyState === 1) {
        // Buscar usuario existente
        let user = await User.findOne({ username: userData.username });
        
        if (user) {
          // Actualizar usuario existente
          if (userData.password) user.password = userData.password;
          if (userData.credits !== undefined) user.credits = userData.credits;
          return await user.save();
        } else {
          // Crear nuevo usuario
          return await User.create(userData);
        }
      } else {
        // Modo memoria
        const index = memoryDB.users.findIndex(u => u.username === userData.username);
        if (index >= 0) {
          memoryDB.users[index] = userData;
        } else {
          memoryDB.users.push(userData);
        }
        return userData;
      }
    } catch (error) {
      console.error('Error en saveUser:', error);
      throw error;
    }
  }
};

// ================================
// TWILIO
// ================================
let twilioClient = null;
if (process.env.TWILIO_SID && process.env.TWILIO_TOKEN) {
  twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);
  console.log('📞 Twilio configurado para WhatsApp Business API');
} else {
  console.warn('⚠️  Twilio no configurado. WhatsApp Business API no disponible.');
}

// ================================
// ENDPOINTS PRINCIPALES
// ================================

app.get('/', (req, res) => {
  res.json({
    status: '🚀 Sistema de Cobranza activo',
    environment: isRender ? 'Render' : 'Local',
    mongo: mongoose.connection.readyState === 1 ? 'Conectado' : 'Memoria',
    whatsapp: twilioClient ? 'Twilio API' : 'Simulación',
    url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`
  });
});

// Health check para Render
app.get('/health', (req, res) => {
  const mongoStatus = mongoose.connection.readyState;
  res.status(mongoStatus === 1 ? 200 : 503).json({ 
    status: mongoStatus === 1 ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    mongo: mongoStatus === 1 ? 'connected' : 'disconnected',
    mongoState: mongoStatus
  });
});

// Status endpoint
app.get('/status', async (req, res) => {
  try {
    const mongoStatus = mongoose.connection.readyState;
    const adminUser = await db.findUser({ username: 'admin' });
    
    res.json({
      server: 'active',
      timestamp: new Date().toISOString(),
      mongo: {
        state: mongoStatus,
        status: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoStatus] || 'unknown',
        connected: mongoStatus === 1
      },
      admin: {
        exists: !!adminUser,
        credits: adminUser ? adminUser.credits : 0
      },
      environment: process.env.NODE_ENV || 'development',
      render: isRender,
      url: process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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
        // Crear usuario admin automáticamente
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const adminUser = {
          username: 'admin',
          password: hashedPassword,
          credits: 100
        };
        await db.saveUser(adminUser);
        
        return res.json({ 
          success: true, 
          user: { username: 'admin', credits: 100 },
          demo: true 
        });
      }
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }
    
    // Verificar contraseña
    const ok = user.password === password || await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });
    
    res.json({ 
      success: true, 
      user: { 
        username: user.username, 
        credits: user.credits 
      } 
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Enviar WhatsApp usando Twilio API o simulación
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
    
    // OPCIÓN 1: Usar Twilio WhatsApp Business API
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
    
    // OPCIÓN 2: Simular envío
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
    res.json({ username: user.username, credits: user.credits });
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
    
    if (!name || !phone) {
      return res.status(400).json({ error: 'Nombre y teléfono requeridos' });
    }
    
    if (mongoose.connection.readyState === 1) {
      const client = new Client({ name, phone, debt: debt || 0, status: 'pending' });
      await client.save();
      res.json(client);
    } else {
      const newClient = { 
        id: Date.now().toString(), 
        name, 
        phone, 
        debt: debt || 0, 
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
// CREAR ADMIN AUTOMÁTICO
// ================================
async function createDefaultAdmin() {
  try {
    console.log('🔍 Verificando usuario admin...');
    const adminExists = await db.findUser({ username: 'admin' });
    
    if (!adminExists) {
      console.log('👑 Creando usuario admin por defecto...');
      const hashedPassword = await bcrypt.hash('admin123', 10);
      
      const adminUser = {
        username: 'admin',
        password: hashedPassword,
        credits: 100
      };
      
      await db.saveUser(adminUser);
      console.log('✅ Usuario admin creado exitosamente');
    } else {
      console.log('✅ Usuario admin ya existe');
    }
  } catch (error) {
    console.error('❌ Error creando admin:', error.message);
  }
}

// Esperar a que MongoDB esté listo
if (isRender) {
  const waitForMongo = setInterval(() => {
    if (mongoose.connection.readyState === 1) {
      clearInterval(waitForMongo);
      setTimeout(createDefaultAdmin, 3000);
    }
  }, 1000);
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