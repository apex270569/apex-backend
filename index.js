const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { ethers } = require('ethers');

// Configuración de la Billetera Maestra
const MASTER_SEED = process.env.MASTER_SEED_PHRASE;
const POLYGON_RPC = 'https://polygon-rpc.com'; // Conexión a la red de Polygon

// Función para generar una dirección derivada para un usuario
function generarDireccionUsuario(userId) {
    // Deriva una clave privada única a partir de la semilla + el ID del usuario
    const hdNode = ethers.HDNodeWallet.fromPhrase(MASTER_SEED);
    const childNode = hdNode.derivePath(`m/44'/60'/0'/0/${userId}`);
    return { 
        address: childNode.address, 
        privateKey: childNode.privateKey // Esta clave se usa para firmar retiros, no se envía al frontend
    };
}

// Función para verificar el saldo de una dirección en la blockchain
async function verificarSaldoBlockchain(address) {
    try {
        const provider = new ethers.JsonRpcProvider(POLYGON_RPC);
        const balanceWei = await provider.getBalance(address);
        // Convertir de Wei a ETH (Polygon usa la misma nomenclatura)
        return ethers.formatEther(balanceWei);
    } catch (error) {
        console.error("Error verificando saldo:", error);
        return "0.0";
    }
}

const app = express();
app.use(cors());
app.use(express.json());

// Conexión a la Base de Datos (Render PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ============================================================
// RUTAS DE LA API
// ============================================================

// 1. Registro de Usuario
app.post('/api/register', async (req, res) => {
  try {
    const { telefono, nombre, apellido, username, password, codigo_inv } = req.body;
    
    // Verificar si el usuario ya existe
    const userExist = await pool.query('SELECT * FROM usuarios WHERE telefono = $1', [telefono]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ error: 'El teléfono ya está registrado' });
    }

    // Encriptar contraseña
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Generar dirección de billetera derivada
    const walletData = generarDireccionUsuario(Date.now()); 
    const polygonAddress = walletData.address;

    // Insertar nuevo usuario
    const result = await pool.query(
      `INSERT INTO usuarios (telefono, nombre, apellido, username, password_hash, balance, puntos, plan, codigo_referido, es_admin, es_super_admin, fecha_registro, polygon_address) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [telefono, nombre, apellido, username, passwordHash, 0, 0, 'Sin plan', 'APEX' + Math.floor(Math.random() * 100000), false, false, new Date(), polygonAddress]
    );

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 2. Login de Usuario
app.post('/api/login', async (req, res) => {
  try {
    const { loginInput, password } = req.body;

    // Buscar usuario por teléfono o username
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE telefono = $1 OR username = $2',
      [loginInput, loginInput]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const user = result.rows[0];

    // Verificar contraseña
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    // Generar Token JWT
    const token = jwt.sign(
      { id: user.id, telefono: user.telefono, es_admin: user.es_admin },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ success: true, token, user });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 3. Obtener datos del usuario logueado
app.get('/api/user/:telefono', async (req, res) => {
  try {
    const { telefono } = req.params;
    const result = await pool.query('SELECT * FROM usuarios WHERE telefono = $1', [telefono]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// 4. Actualizar Saldo y Puntos
app.post('/api/update-balance', async (req, res) => {
  try {
    const { telefono, balance, puntos } = req.body;
    await pool.query(
      'UPDATE usuarios SET balance = $1, puntos = $2 WHERE telefono = $3',
      [balance, puntos, telefono]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Ruta para que el usuario verifique su saldo desde la blockchain
app.get('/api/check-balance/:telefono', async (req, res) => {
    try {
        const { telefono } = req.params;
        // Obtener la dirección del usuario desde la BD
        const result = await pool.query('SELECT polygon_address FROM usuarios WHERE telefono = $1', [telefono]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        const address = result.rows[0].polygon_address;
        const balance = await verificarSaldoBlockchain(address);
        res.json({ address, balance });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Error verificando saldo' });
    }
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});