import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { Resend } from 'resend';
import pkg from 'pg';

const { Pool } = pkg;
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
      html: `
