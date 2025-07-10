require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración para Clever Cloud
const dbConfig = {
  host: process.env.MYSQL_ADDON_HOST || 'bx49uyepnlw7zovqoiy1-mysql.services.clever-cloud.com',
  user: process.env.MYSQL_ADDON_USER || 'u8fwbabmhaujhodp',
  password: process.env.MYSQL_ADDON_PASSWORD || 'WNRnvJLg0N11Lz5Uiffv',
  database: process.env.MYSQL_ADDON_DB || 'bx49uyepnlw7zovqoiy1',
  port: process.env.MYSQL_ADDON_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Configuración de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Pool de conexiones a la base de datos
const pool = mysql.createPool(dbConfig);

// Middleware de autenticación
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

// Función para ejecutar consultas SQL
async function query(sql, params) {
  const connection = await pool.getConnection();
  try {
    const [results] = await connection.execute(sql, params);
    return results;
  } finally {
    connection.release();
  }
}

// Crear tablas (ejecutar solo una vez)
async function createTables() {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS niveles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(50) NOT NULL,
        descripcion TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS grados (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nivel_id INT NOT NULL,
        nombre VARCHAR(50) NOT NULL,
        descripcion TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (nivel_id) REFERENCES niveles(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        rol ENUM('profesor', 'coordinador', 'admin') NOT NULL,
        nivel_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (nivel_id) REFERENCES niveles(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS alumnos (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        grado_id INT NOT NULL,
        email_tutor VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (grado_id) REFERENCES grados(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS asistencias (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fecha DATE NOT NULL,
        grado_id INT NOT NULL,
        profesor_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (grado_id) REFERENCES grados(id),
        FOREIGN KEY (profesor_id) REFERENCES usuarios(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS asistencia_detalle (
        id INT AUTO_INCREMENT PRIMARY KEY,
        asistencia_id INT NOT NULL,
        alumno_id INT NOT NULL,
        estado ENUM('presente', 'ausente', 'tarde') NOT NULL,
        uniforme_completo BOOLEAN DEFAULT TRUE,
        observaciones TEXT,
        FOREIGN KEY (asistencia_id) REFERENCES asistencias(id),
        FOREIGN KEY (alumno_id) REFERENCES alumnos(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS reportes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        tipo ENUM('uniforme', 'asistencia', 'general') NOT NULL,
        alumno_id INT,
        profesor_id INT NOT NULL,
        detalle TEXT NOT NULL,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (alumno_id) REFERENCES alumnos(id),
        FOREIGN KEY (profesor_id) REFERENCES usuarios(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS horarios (
        id INT AUTO_INCREMENT PRIMARY KEY,
        grado_id INT NOT NULL,
        dia_semana ENUM('Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo') NOT NULL,
        hora_inicio TIME NOT NULL,
        hora_fin TIME NOT NULL,
        FOREIGN KEY (grado_id) REFERENCES grados(id)
      )
    `);

    console.log('Tablas creadas exitosamente');
  } catch (error) {
    console.error('Error al crear tablas:', error);
  }
}

// Llamar a la función para crear tablas (descomentar solo la primera vez)
// createTables();

// RUTAS DE AUTENTICACIÓN
// Registro (solo admin)
app.post('/api/register', authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }

  const { nombre, email, password, rol, nivel_id } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await query(
      'INSERT INTO usuarios (nombre, email, password, rol, nivel_id) VALUES (?, ?, ?, ?, ?)',
      [nombre, email, hashedPassword, rol, nivel_id]
    );
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(400).json({ message: 'Error al registrar usuario', error });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [user] = await query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ message: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, nivel_id: user.nivel_id },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '8h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error en el servidor', error });
  }
});

// Recuperación de contraseña
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const [user] = await query('SELECT * FROM usuarios WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ message: 'Usuario no encontrado' });

    const resetToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secret_key', { expiresIn: '15m' });
    const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `<p>Haga clic <a href="${resetLink}">aquí</a> para restablecer su contraseña. Este enlace expirará en 15 minutos.</p>`
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'Correo de recuperación enviado' });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar correo', error });
  }
});

// RUTAS DE PROFESOR
// Obtener grados por nivel del profesor
app.get('/api/grados', authenticateToken, async (req, res) => {
  try {
    const grados = await query(
      'SELECT g.* FROM grados g JOIN niveles n ON g.nivel_id = n.id WHERE n.id = ?',
      [req.user.nivel_id]
    );
    res.json(grados);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener grados', error });
  }
});

// Obtener alumnos por grado
app.get('/api/alumnos/:grado_id', authenticateToken, async (req, res) => {
  try {
    const alumnos = await query('SELECT * FROM alumnos WHERE grado_id = ?', [req.params.grado_id]);
    res.json(alumnos);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener alumnos', error });
  }
});

// Registrar asistencia
app.post('/api/asistencias', authenticateToken, async (req, res) => {
  const { grado_id, fecha, alumnos } = req.body;

  try {
    // Crear registro de asistencia
    const [result] = await query(
      'INSERT INTO asistencias (fecha, grado_id, profesor_id) VALUES (?, ?, ?)',
      [fecha, grado_id, req.user.id]
    );
    const asistencia_id = result.insertId;

    // Registrar detalle de asistencia para cada alumno
    for (const alumno of alumnos) {
      await query(
        'INSERT INTO asistencia_detalle (asistencia_id, alumno_id, estado, uniforme_completo, observaciones) VALUES (?, ?, ?, ?, ?)',
        [asistencia_id, alumno.id, alumno.estado, alumno.uniforme_completo, alumno.observaciones]
      );
    }

    res.status(201).json({ message: 'Asistencia registrada exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar asistencia', error });
  }
});

// Enviar reporte
app.post('/api/reportes', authenticateToken, async (req, res) => {
  const { tipo, alumno_id, detalle } = req.body;

  try {
    await query(
      'INSERT INTO reportes (tipo, alumno_id, profesor_id, detalle) VALUES (?, ?, ?, ?)',
      [tipo, alumno_id, req.user.id, detalle]
    );

    // Si es un reporte de uniforme, enviar correo al tutor
    if (tipo === 'uniforme' && alumno_id) {
      const [alumno] = await query('SELECT * FROM alumnos WHERE id = ?', [alumno_id]);
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: alumno.email_tutor,
        subject: 'Reporte de uniforme escolar',
        html: `<p>Estimado tutor de ${alumno.nombre},</p>
               <p>Se ha registrado un reporte por incumplimiento del uniforme:</p>
               <p>${detalle}</p>
               <p>Por favor tomar las medidas correspondientes.</p>`
      };
      await transporter.sendMail(mailOptions);
    }

    res.status(201).json({ message: 'Reporte enviado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar reporte', error });
  }
});

// RUTAS DE COORDINADOR
// Obtener estadísticas por nivel
app.get('/api/estadisticas/niveles', authenticateToken, async (req, res) => {
  if (req.user.rol !== 'coordinador' && req.user.rol !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }

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

// RUTAS DE ADMINISTRADOR
// Gestión de niveles
app.post('/api/niveles', authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }

  const { nombre, descripcion } = req.body;

  try {
    await query(
      'INSERT INTO niveles (nombre, descripcion) VALUES (?, ?)',
      [nombre, descripcion]
    );
    res.status(201).json({ message: 'Nivel creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear nivel', error });
  }
});

// Gestión de grados
app.post('/api/grados', authenticateToken, async (req, res) => {
  if (req.user.rol !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }

  const { nivel_id, nombre, descripcion } = req.body;

  try {
    await query(
      'INSERT INTO grados (nivel_id, nombre, descripcion) VALUES (?, ?, ?)',
      [nivel_id, nombre, descripcion]
    );
    res.status(201).json({ message: 'Grado creado exitosamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear grado', error });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});