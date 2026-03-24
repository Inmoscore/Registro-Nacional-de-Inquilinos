import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Seguridad
app.use(helmet());
app.use(cors());
app.use(express.json());

// Límite de peticiones (100 por 15 minutos)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Ruta de prueba - Health Check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'InmoScore API funcionando correctamente',
    timestamp: new Date().toISOString()
  });
});

// Ruta principal
app.get('/', (req, res) => {
  res.json({ 
    message: 'Bienvenido a InmoScore API',
    version: '1.0.0',
    description: 'API para consulta de historial de arrendatarios en Colombia',
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      tenants: '/api/tenants',
      reports: '/api/reports'
    }
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor InmoScore corriendo en puerto ${PORT}`);
  console.log(`📍 URL: http://localhost:${PORT}`);
});