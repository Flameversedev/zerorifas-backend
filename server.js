const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');
const { Pool } = require('pg');

const app = express();

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const resend = new Resend(process.env.RESEND_API_KEY);

// Ruta de comprobación
app.get('/', (req, res) => {
  res.send('Servidor ZeroRifas activo y funcionando.');
});

// Registro de usuario y envío de OTP
app.post('/api/auth/registro', async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    const userCheck = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'El correo ya está registrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();
    const expira = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      `INSERT INTO usuarios (nombre, email, password_hash, codigo_otp, otp_expira) 
       VALUES ($1, $2, $3, $4, $5)`,
      [nombre, email, hashedPassword, codigoOTP, expira]
    );

    await resend.emails.send({
      from: 'ZeroRifas ',
      to: email,
      subject: 'Código de Verificación - ZeroRifas',
      html: `¡Hola ${nombre}!
Tu código de verificación para completar el registro en ZeroRifas es:

${codigoOTP}
Este código vencerá en 10 minutos.

  `
});

res.status(201).json({ mensaje: 'Usuario registrado. Revisa tu correo para el código OTP.' });
} catch (error) {
console.error(error);
res.status(500).json({ error: 'Error interno en el servidor.' });
}
});

// Verificación de OTP
app.post('/api/auth/verificar-otp', async (req, res) => {
const { email, codigoOTP } = req.body;

try {
const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });

const usuario = result.rows[0];

if (usuario.codigo_otp !== codigoOTP) {
  return res.status(400).json({ error: 'Código OTP incorrecto.' });
}

if (new Date() > new Date(usuario.otp_expira)) {
  return res.status(400).json({ error: 'El código OTP ha expirado.' });
}

await pool.query('UPDATE usuarios SET email_verificado = TRUE, codigo_otp = NULL WHERE email = $1', [email]);

res.json({ mensaje: 'Correo verificado con éxito.' });
} catch (error) {
console.error(error);
res.status(500).json({ error: 'Error al verificar el código.' });
}
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Servidor en puerto ' + PORT));
