// ✅ server.js - Backend actualizado con rutas bajo /api
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Middleware CORS y JSON
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// 📦 Configuración de base de datos Clever Cloud
const dbConfig = {
  host: process.env.MYSQL_ADDON_HOST,
  user: process.env.MYSQL_ADDON_USER,
  password: process.env.MYSQL_ADDON_PASSWORD,
  database: process.env.MYSQL_ADDON_DB,
  port: process.env.MYSQL_ADDON_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

// ✉️ Configuración de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// 🔐 Middleware de autenticación
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// 🔧 Función para ejecutar consultas SQL
async function query(sql, params) {
  const connection = await pool.getConnection();
  try {
    const [results] = await connection.execute(sql, params);
    return results;
  } finally {
    connection.release();
  }
}

// ✅ Rutas
const base = '/api';

// 🔐 Login
// 🔐 Login corregido
app.post(`${base}/login`, async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const users = await query('SELECT * FROM usuarios WHERE email = ?', [email]);
      if (!users.length) return res.status(400).json({ message: 'Usuario no encontrado' });
  
      const user = users[0]; // ← tomamos el primer usuario de la consulta
  
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).json({ message: 'Contraseña incorrecta' });
  
      const token = jwt.sign(
        {
          id: user.id,
          nombre: user.nombre,
          email: user.email,
          rol: user.rol,
          nivel_id: user.nivel_id,
        },
        process.env.JWT_SECRET || 'secret_key',
        { expiresIn: '8h' }
      );
  
      res.json({ token });
    } catch (error) {
      res.status(500).json({ message: 'Error en el servidor', error });
    }
  });
  
// 📧 Recuperar contraseña
app.post(`${base}/forgot-password`, async (req, res) => {
  const { email } = req.body;
  try {
    const [user] = await query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ message: 'Usuario no encontrado' });

    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `<p>Haz clic <a href="${resetLink}">aquí</a> para restablecer tu contraseña.</p>`
    });

    res.json({ message: 'Correo de recuperación enviado' });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar correo', error });
  }
});

// 👤 Registro de usuario (solo admin)
app.post(`${base}/register`, authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { nombre, email, password, rol, nivel_id } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await query('INSERT INTO usuarios (nombre, email, password, rol, nivel_id) VALUES (?, ?, ?, ?, ?)', [nombre, email, hashedPassword, rol, nivel_id]);
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(400).json({ message: 'Error al registrar usuario', error });
  }
});

// 📚 Obtener grados del nivel asignado (profesor)
app.get(`${base}/grados`, authenticateToken, async (req, res) => {
  try {
    const grados = await query('SELECT * FROM grados WHERE nivel_id = ?', [req.user.nivel_id]);
    res.json(grados);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener grados', error });
  }
});

// 🎓 Obtener alumnos por grado
app.get(`${base}/alumnos/:grado_id`, authenticateToken, async (req, res) => {
  try {
    const alumnos = await query('SELECT * FROM alumnos WHERE grado_id = ?', [req.params.grado_id]);
    res.json(alumnos);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener alumnos', error });
  }
});

// ✅ Registrar asistencia
app.post(`${base}/asistencias`, authenticateToken, async (req, res) => {
  const { grado_id, fecha, alumnos } = req.body;
  try {
    const [result] = await query('INSERT INTO asistencias (fecha, grado_id, profesor_id) VALUES (?, ?, ?)', [fecha, grado_id, req.user.id]);
    const asistencia_id = result.insertId;
    for (const alumno of alumnos) {
      await query('INSERT INTO asistencia_detalle (asistencia_id, alumno_id, estado, uniforme_completo, observaciones) VALUES (?, ?, ?, ?, ?)', [asistencia_id, alumno.id, alumno.estado, alumno.uniforme_completo, alumno.observaciones]);
    }
    res.status(201).json({ message: 'Asistencia registrada exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar asistencia', error });
  }
});

// 📝 Enviar reporte
app.post(`${base}/reportes`, authenticateToken, async (req, res) => {
  const { tipo, alumno_id, detalle } = req.body;
  try {
    await query('INSERT INTO reportes (tipo, alumno_id, profesor_id, detalle) VALUES (?, ?, ?, ?)', [tipo, alumno_id, req.user.id, detalle]);
    if (tipo === 'uniforme' && alumno_id) {
      const [alumno] = await query('SELECT * FROM alumnos WHERE id = ?', [alumno_id]);
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: alumno.email_tutor,
        subject: 'Reporte de uniforme escolar',
        html: `<p>Tutor de ${alumno.nombre},</p><p>${detalle}</p>`
      });
    }
    res.status(201).json({ message: 'Reporte enviado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar reporte', error });
  }
});

// 📊 Estadísticas por nivel (admin y coordinador)
app.get(`${base}/estadisticas/niveles`, authenticateToken, async (req, res) => {
  if (!['admin', 'coordinador'].includes(req.user.rol)) return res.status(403).json({ message: 'No autorizado' });
  try {
    const estadisticas = await query(`
      SELECT n.id, n.nombre,
             COUNT(DISTINCT g.id) AS total_grados,
             COUNT(DISTINCT a.id) AS total_alumnos,
             AVG(CASE WHEN ad.estado = 'presente' THEN 1 ELSE 0 END) * 100 AS promedio_asistencia
      FROM niveles n
      LEFT JOIN grados g ON n.id = g.nivel_id
      LEFT JOIN alumnos a ON g.id = a.grado_id
      LEFT JOIN asistencias ast ON g.id = ast.grado_id
      LEFT JOIN asistencia_detalle ad ON ast.id = ad.asistencia_id
      GROUP BY n.id, n.nombre
    `);
    res.json(estadisticas);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener estadísticas', error });
  }
});

// ➕ Crear nivel y grado (solo admin)
app.post(`${base}/niveles`, authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { nombre, descripcion } = req.body;
  try {
    await query('INSERT INTO niveles (nombre, descripcion) VALUES (?, ?)', [nombre, descripcion]);
    res.status(201).json({ message: 'Nivel creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear nivel', error });
  }
});

app.post(`${base}/grados`, authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') return res.status(403).json({ message: 'No autorizado' });
  const { nivel_id, nombre, descripcion } = req.body;
  try {
    await query('INSERT INTO grados (nivel_id, nombre, descripcion) VALUES (?, ?, ?)', [nivel_id, nombre, descripcion]);
    res.status(201).json({ message: 'Grado creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear grado', error });
  }
});

// 🔄 Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});