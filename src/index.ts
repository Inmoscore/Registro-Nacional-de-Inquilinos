import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Seguridad con Helmet
app.use(helmet());

// Configuración CORS - Permitir requests desde el frontend en Vercel
app.use(cors({
  origin: [
    'https://inmoscore-frontend.vercel.app',
    'https://inmoscore-frontend-git-main-inmoscore-2369s-projects.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Parser JSON
app.use(express.json());

// Límite de peticiones (100 por 15 minutos)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Demasiadas peticiones desde esta IP, por favor intente más tarde'
});
app.use(limiter);

// ==========================================
// RUTAS DE LA API
// ==========================================

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
      search: '/api/search-tenant',
      report: '/api/report-tenant'
    }
  });
});

// Buscar arrendatario por cédula
app.get('/api/search-tenant', async (req, res) => {
  try {
    const { cedula } = req.query;
    
    if (!cedula) {
      return res.status(400).json({ 
        success: false, 
        message: 'La cédula es requerida' 
      });
    }

    // Aquí iría la lógica para buscar en la base de datos
    // Por ahora devolvemos un ejemplo
    res.json({
      success: true,
      nombre: 'Juan Pérez',
      cedula: cedula,
      score: 85,
      clasificacion: 'Bajo riesgo',
      numero_reportes: 0,
      procesos_judiciales: 0
    });
    
  } catch (error) {
    console.error('Error al buscar arrendatario:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error interno del servidor' 
    });
  }
});

// Reportar arrendatario
app.post('/api/report-tenant', async (req, res) => {
  try {
    const { nombre, cedula, telefono, ciudad, tipo_problema, descripcion } = req.body;
    
    // Validación básica
    if (!nombre || !cedula || !ciudad || !tipo_problema || !descripcion) {
      return res.status(400).json({ 
        success: false, 
        message: 'Todos los campos son requeridos' 
      });
    }

    // Aquí iría la lógica para guardar en la base de datos
    // Por ahora devolvemos éxito
    res.status(201).json({
      success: true,
      message: 'Reporte creado exitosamente',
      data: {
        nombre,
        cedula,
        tipo_problema,
        fecha: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('Error al crear reporte:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error interno del servidor' 
    });
  }
});

// Manejo de rutas no encontradas
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Ruta no encontrada' 
  });
});

// Manejo de errores
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'Error interno del servidor' 
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor InmoScore corriendo en puerto ${PORT}`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔒 CORS configurado para: https://inmoscore-frontend.vercel.app`);
});