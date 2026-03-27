import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// ==========================================
// TIPOS PERSONALIZADOS
// ==========================================
interface JwtPayload {
  id: string;
  email: string;
  tipo_usuario: string;
}

interface AuthRequest extends Request {
  user?: JwtPayload;
}

// ==========================================
// CONFIGURACIÓN SUPABASE
// ==========================================
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Error: Faltan variables de entorno de Supabase');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

// ==========================================
// MIDDLEWARES
// ==========================================
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'https://inmoscore-frontend.vercel.app'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, message: 'Demasiadas peticiones desde esta IP' }
});
app.use(limiter);

// ==========================================
// UTILIDADES
// ==========================================

// Middleware de autenticación
const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ success: false, message: 'Token no proporcionado' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-fallback') as JwtPayload;
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ success: false, message: 'Token inválido' });
    return;
  }
};

// Calcular score de arrendatario
const calculateScore = (reportes: number, procesos: number): number => {
  let score = 100;
  score -= (reportes * 20);
  score -= (procesos * 30);
  return Math.max(0, score);
};

const getClasificacion = (score: number): string => {
  if (score >= 80) return 'bajo';
  if (score >= 50) return 'medio';
  return 'alto';
};

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================

// Registro
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { nombre, email, password, tipo_usuario } = req.body;

    // Validar email único
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existing) {
      res.status(400).json({ success: false, message: 'El email ya está registrado' });
      return;
    }

    // Hashear password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        nombre,
        email,
        password: hashedPassword,
        tipo_usuario: tipo_usuario || 'propietario',
        fecha_registro: new Date().toISOString(),
        email_verificado: false
      })
      .select()
      .single();

    if (error) throw error;

    // Generar token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, tipo_usuario: newUser.tipo_usuario },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser.id,
        nombre: newUser.nombre,
        email: newUser.email,
        tipo_usuario: newUser.tipo_usuario
      }
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ success: false, message: 'Error al registrar usuario' });
  }
});

// Login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      res.status(401).json({ success: false, message: 'Credenciales inválidas' });
      return;
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      res.status(401).json({ success: false, message: 'Credenciales inválidas' });
      return;
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, tipo_usuario: user.tipo_usuario },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        nombre: user.nombre,
        email: user.email,
        tipo_usuario: user.tipo_usuario
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ success: false, message: 'Error al iniciar sesión' });
  }
});

// ==========================================
// RUTAS DE ARRENDATARIOS
// ==========================================

// Buscar arrendatario por cédula (PROTEGIDO)
app.get('/api/tenants/search', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const { cedula } = req.query;
    
    if (!cedula || typeof cedula !== 'string') {
      res.status(400).json({ 
        success: false, 
        message: 'La cédula es requerida' 
      });
      return;
    }

    // Validar formato
    if (!/^\d{6,10}$/.test(cedula)) {
      res.status(400).json({
        success: false,
        message: 'Formato de cédula inválido (6-10 dígitos)'
      });
      return;
    }

    // Buscar tenant
    const { data: tenant } = await supabase
      .from('tenants')
      .select('*')
      .eq('cedula', cedula)
      .single();

    // Si no existe, devolver null (no es error)
    if (!tenant) {
      res.json({
        success: true,
        cedula: cedula,
        nombre: null,
        score: null,
        clasificacion: null,
        total_reportes: 0,
        reportes_aprobados: 0,
        procesos_judiciales: 0,
        detalle_reportes: [],
        detalle_procesos: []
      });
      return;
    }

    // Obtener reportes aprobados
    const { data: reportes } = await supabase
      .from('reports')
      .select('*')
      .eq('tenant_id', tenant.id)
      .eq('estado', 'aprobado');

    // Obtener procesos judiciales
    const { data: procesos } = await supabase
      .from('legal_cases')
      .select('*')
      .eq('cedula', cedula);

    const totalReportes = reportes?.length || 0;
    const totalProcesos = procesos?.length || 0;
    const score = calculateScore(totalReportes, totalProcesos);
    const clasificacion = getClasificacion(score);

    res.json({
      success: true,
      cedula: tenant.cedula,
      nombre: tenant.nombre,
      score: score,
      clasificacion: clasificacion,
      total_reportes: totalReportes,
      reportes_aprobados: totalReportes,
      procesos_judiciales: totalProcesos,
      detalle_reportes: reportes || [],
      detalle_procesos: procesos || []
    });
  } catch (error) {
    console.error('Error al buscar arrendatario:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error interno del servidor' 
    });
  }
});

// ==========================================
// RUTAS DE REPORTES
// ==========================================

// Crear reporte (PROTEGIDO)
app.post('/api/reports', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const { nombre, cedula, telefono, ciudad, tipo_problema, descripcion } = req.body;
    
    // Validaciones
    if (!nombre || !cedula || !ciudad || !tipo_problema || !descripcion) {
      res.status(400).json({ 
        success: false, 
        message: 'Todos los campos son requeridos' 
      });
      return;
    }

    if (!/^\d{6,10}$/.test(cedula)) {
      res.status(400).json({
        success: false,
        message: 'Cédula inválida (6-10 dígitos)'
      });
      return;
    }

    // Buscar o crear tenant
    let { data: tenant } = await supabase
      .from('tenants')
      .select('id')
      .eq('cedula', cedula)
      .single();

    if (!tenant) {
      // Crear nuevo tenant
      const { data: newTenant, error: tenantError } = await supabase
        .from('tenants')
        .insert({
          nombre: nombre.toUpperCase(),
          cedula,
          telefono: telefono || null,
          ciudad: ciudad.toUpperCase(),
          fecha_creacion: new Date().toISOString()
        })
        .select()
        .single();

      if (tenantError) throw tenantError;
      tenant = newTenant;
    }

    // Crear reporte
    const { data: report, error: reportError } = await supabase
      .from('reports')
      .insert({
        tenant_id: tenant!.id,
        tipo_problema,
        descripcion,
        fecha_reporte: new Date().toISOString(),
        estado: 'pendiente',
        reportado_por: req.user?.id || null
      })
      .select()
      .single();

    if (reportError) throw reportError;

    res.status(201).json({
      success: true,
      message: 'Reporte creado exitosamente y pendiente de revisión',
      report
    });
  } catch (error) {
    console.error('Error al crear reporte:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error interno del servidor' 
    });
  }
});

// ==========================================
// RUTAS ADMIN
// ==========================================

// Obtener reportes pendientes
app.get('/api/admin/reports', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    // Verificar si es admin
    if (req.user?.tipo_usuario !== 'admin') {
      res.status(403).json({ success: false, message: 'Acceso denegado' });
      return;
    }

    const { data: reports } = await supabase
      .from('reports')
      .select(`
        *,
        tenants (
          nombre,
          cedula,
          ciudad
        )
      `)
      .eq('estado', 'pendiente')
      .order('fecha_reporte', { ascending: false });

    res.json({ success: true, reports: reports || [] });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Error interno' });
  }
});

// Aprobar/Rechazar reporte
app.put('/api/admin/reports/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.tipo_usuario !== 'admin') {
      res.status(403).json({ success: false, message: 'Acceso denegado' });
      return;
    }

    const { id } = req.params;
    const { estado } = req.body;

    if (!['aprobado', 'rechazado'].includes(estado)) {
      res.status(400).json({ success: false, message: 'Estado inválido' });
      return;
    }

    const { data: report } = await supabase
      .from('reports')
      .update({ estado })
      .eq('id', id)
      .select()
      .single();

    res.json({
      success: true,
      message: `Reporte ${estado === 'aprobado' ? 'aprobado' : 'rechazado'} exitosamente`,
      report
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error interno' });
  }
});

// ==========================================
// HEALTH CHECK
// ==========================================
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'OK', 
    message: 'InmoScore API conectada a Supabase',
    timestamp: new Date().toISOString()
  });
});

// ==========================================
// MANEJO DE ERRORES
// ==========================================
app.use((req: Request, res: Response) => {
  res.status(404).json({ 
    success: false, 
    message: 'Ruta no encontrada',
    path: req.path
  });
});

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ 
    success: false, 
    message: 'Error interno del servidor' 
  });
});

// ==========================================
// INICIAR SERVIDOR
// ==========================================
app.listen(PORT, async () => {
  console.log(`🚀 Servidor InmoScore corriendo en puerto ${PORT}`);
  
  // Verificar conexión a Supabase
  try {
    const { data, error } = await supabase.from('tenants').select('count');
    if (error) throw error;
    console.log('✅ Conexión a Supabase establecida');
  } catch (err) {
    console.error('❌ Error conectando a Supabase:', err);
  }
});