const express = require('express');
const twilio = require('twilio');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ✅ CREDENCIALES DE TWILIO
const ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_SMS = process.env.TWILIO_PHONE_SMS;
const TWILIO_PHONE_CALL = process.env.TWILIO_PHONE_CALL;

// Validar variables de entorno
if (!ACCOUNT_SID || !AUTH_TOKEN || !TWILIO_PHONE_SMS || !TWILIO_PHONE_CALL) {
  console.error('❌ ERROR: Faltan variables de entorno de Twilio');
  console.error('Configura: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_SMS, TWILIO_PHONE_CALL');
  process.exit(1);
}

const client = twilio(ACCOUNT_SID, AUTH_TOKEN);

// Base de datos en memoria (para producción usar MongoDB, PostgreSQL, etc.)
let campaignStats = {
  totalSent: 0,
  totalCalls: 0,
  errors: 0,
  callsAnswered: 0,
  callsRejected: 0,
  callsBusy: 0,
  callsNoAnswer: 0
};

// 📱 Endpoint para enviar SMS
app.post('/api/send-sms', async (req, res) => {
  try {
    const { to, message } = req.body;
    
    if (!to || !message) {
      return res.status(400).json({ 
        success: false, 
        error: 'Faltan parámetros: to y message son requeridos' 
      });
    }
    
    console.log(`📱 Enviando SMS a ${to}...`);
    
    const result = await client.messages.create({
      body: message,
      from: TWILIO_PHONE_SMS,
      to: to
    });
    
    campaignStats.totalSent++;
    
    console.log(`✅ SMS enviado. SID: ${result.sid}, Status: ${result.status}`);
    res.json({ 
      success: true, 
      sid: result.sid,
      status: result.status
    });
  } catch (error) {
    campaignStats.errors++;
    console.error('❌ Error al enviar SMS:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// 📞 Endpoint para hacer llamadas
app.post('/api/make-call', async (req, res) => {
  try {
    const { to, script } = req.body;
    
    if (!to || !script) {
      return res.status(400).json({ 
        success: false, 
        error: 'Faltan parámetros: to y script son requeridos' 
      });
    }
    
    console.log(`📞 Llamando a ${to}...`);
    
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
      statusCallback: `${process.env.BASE_URL || 'http://localhost:3000'}/api/call-status`,
      statusCallbackEvent: ['completed']
    });
    
    campaignStats.totalCalls++;
    
    console.log(`✅ Llamada iniciada. SID: ${result.sid}, Status: ${result.status}`);
    res.json({ 
      success: true, 
      sid: result.sid,
      status: result.status
    });
  } catch (error) {
    campaignStats.errors++;
    console.error('❌ Error al hacer llamada:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// 📊 Webhook para recibir estado de llamadas
app.post('/api/call-status', (req, res) => {
  const { CallStatus, CallSid, To } = req.body;
  
  console.log(`📊 Estado de llamada ${CallSid}: ${CallStatus}`);
  
  switch(CallStatus) {
    case 'completed':
      campaignStats.callsAnswered++;
      break;
    case 'busy':
      campaignStats.callsBusy++;
      break;
    case 'no-answer':
      campaignStats.callsNoAnswer++;
      break;
    case 'failed':
    case 'canceled':
      campaignStats.callsRejected++;
      break;
  }
  
  res.sendStatus(200);
});

// 📈 Endpoint para obtener estadísticas
app.get('/api/stats', (req, res) => {
  res.json({
    success: true,
    stats: campaignStats
  });
});

// 🔄 Endpoint para resetear estadísticas
app.post('/api/reset-stats', (req, res) => {
  campaignStats = {
    totalSent: 0,
    totalCalls: 0,
    errors: 0,
    callsAnswered: 0,
    callsRejected: 0,
    callsBusy: 0,
    callsNoAnswer: 0
  };
  res.json({ success: true, message: 'Estadísticas reseteadas' });
});

// 🔍 Endpoint para verificar estado de mensaje/llamada
app.get('/api/status/:sid', async (req, res) => {
  try {
    const { sid } = req.params;
    
    // Intentar obtener como mensaje primero
    try {
      const message = await client.messages(sid).fetch();
      return res.json({
        success: true,
        type: 'message',
        status: message.status,
        to: message.to,
        from: message.from,
        dateCreated: message.dateCreated
      });
    } catch (e) {
      // Si falla, intentar como llamada
      const call = await client.calls(sid).fetch();
      return res.json({
        success: true,
        type: 'call',
        status: call.status,
        to: call.to,
        from: call.from,
        duration: call.duration,
        dateCreated: call.dateCreated
      });
    }
  } catch (error) {
    res.status(404).json({ 
      success: false, 
      error: 'No se encontró el SID especificado' 
    });
  }
});

// 🧪 Endpoint de prueba
app.get('/api/test', (req, res) => {
  res.json({ 
    status: 'OK',
    message: '🚀 Servidor de cobranza Twilio funcionando correctamente',
    twilio_phone_sms: TWILIO_PHONE_SMS,
    twilio_phone_call: TWILIO_PHONE_CALL,
    account_configured: true,
    current_stats: campaignStats
  });
});

// 🌐 Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('🚀 SERVIDOR DE COBRANZA TWILIO INICIADO');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`📱 Número SMS: ${TWILIO_PHONE_SMS} (USA)`);
  console.log(`📞 Número Llamadas: ${TWILIO_PHONE_CALL} (México)`);
  console.log(`\n📋 Endpoints disponibles:`);
  console.log(`   ✅ GET  http://localhost:${PORT}/api/test`);
  console.log(`   📱 POST http://localhost:${PORT}/api/send-sms`);
  console.log(`   📞 POST http://localhost:${PORT}/api/make-call`);
  console.log(`   📊 GET  http://localhost:${PORT}/api/stats`);
  console.log(`   🔍 GET  http://localhost:${PORT}/api/status/:sid`);
  console.log(`   🔄 POST http://localhost:${PORT}/api/reset-stats`);
  console.log('═══════════════════════════════════════════════════\n');
});