const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const cors = require('cors'); // Añadido para CORS

const app = express();
const db = new sqlite3.Database("./database.db");

// Configuración de CORS
const corsOptions = {
  origin: ['https://meek-profiterole-a4990a.netlify.app', 'http://localhost:3000'], // **REEMPLAZA CON TU DOMINIO REAL DE NETLIFY**
  credentials: true, // Permite el envío de cookies de sesión
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Configuración de multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Crear directorio si no existe
    const uploadDir = "public/uploads";
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const nombre = Date.now() + "_" + file.originalname;
    cb(null, nombre);
  }
});
const upload = multer({ storage });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Añadido para manejar JSON
app.use(session({ 
  secret: "amor", 
  resave: false, 
  saveUninitialized: true,
  cookie: {
    secure: false, // Cambiar a true si usas HTTPS en producción
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  }
}));

// Rutas públicas que no requieren login
const rutasPublicas = ["/login", "/register", "/css/", "/js/", "/img/", "/uploads/"];

// Middleware de protección
app.use((req, res, next) => {
  const ruta = req.originalUrl;
  const esPublica = rutasPublicas.some(p => ruta.startsWith(p));
  if (!esPublica && !req.session.user) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
});

// Servir archivos estáticos
app.use(express.static("public"));

// Crear tabla de usuarios
db.run(`CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT UNIQUE,
  pass TEXT
)`);

// Crear tabla de cartas
db.run(`CREATE TABLE IF NOT EXISTS cartas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT,
  contenido TEXT,
  fecha TEXT
)`);

// Tabla para guardar fotos
db.run(`CREATE TABLE IF NOT EXISTS fotos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT,
  user TEXT,
  fecha TEXT
)`);

// Rutas
app.post("/register", async (req, res) => {
  try {
    const { user, pass } = req.body;
    
    if (!user || !pass) {
      return res.status(400).json({ success: false, message: "Usuario y contraseña son requeridos" });
    }

    const hash = await bcrypt.hash(pass, 10);
    
    db.run("INSERT INTO usuarios (user, pass) VALUES (?, ?)", [user, hash], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ success: false, message: "El usuario ya existe" });
        }
        return res.status(500).json({ success: false, message: "Error del servidor" });
      }
      res.json({ success: true, message: "Usuario registrado exitosamente" });
    });
  } catch (error) {
    console.error("Error en registro:", error);
    res.status(500).json({ success: false, message: "Error del servidor" });
  }
});

app.post("/login", (req, res) => {
  const { user, pass } = req.body;
  
  if (!user || !pass) {
    return res.status(400).json({ success: false, message: "Usuario y contraseña son requeridos" });
  }

  db.get("SELECT * FROM usuarios WHERE user = ?", [user], async (err, userRecord) => {
    if (err) {
      return res.status(500).json({ success: false, message: "Error del servidor" });
    }
    
    if (userRecord && await bcrypt.compare(pass, userRecord.pass)) {
      req.session.user = userRecord.user;
      res.json({ success: true, message: "Login exitoso" });
    } else {
      res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos" });
    }
  });
});

app.post("/cartas", (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: "No autorizado" });
  
  const { contenido } = req.body;
  
  if (!contenido || contenido.trim() === '') {
    return res.status(400).json({ success: false, message: "El contenido de la carta es requerido" });
  }
  
  const fecha = new Date().toLocaleString("es-ES");
  
  db.run("INSERT INTO cartas (user, contenido, fecha) VALUES (?, ?, ?)", [req.session.user, contenido.trim(), fecha], function(err) {
    if (err) {
      console.error("Error al guardar carta:", err);
      return res.status(500).json({ success: false, message: "Error al guardar la carta" });
    }
    res.json({ success: true, message: "Carta guardada exitosamente" });
  });
});

// Obtener cartas del usuario
app.get("/cartas", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autorizado" });
  
  db.all("SELECT user, contenido, fecha FROM cartas ORDER BY id DESC", (err, rows) => {
    if (err) {
      console.error("Error al obtener cartas:", err);
      return res.status(500).json([]);
    }
    res.json(rows || []);
  });
});

app.get("/usuario", (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user });
});

app.post("/subir-foto", upload.single("foto"), (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: "No autorizado" });

  if (!req.file) {
    return res.status(400).json({ success: false, message: "No se subió ningún archivo" });
  }

  const filename = req.file.filename;
  const user = req.session.user;
  const fecha = new Date().toLocaleString("es-ES");

  db.run("INSERT INTO fotos (filename, user, fecha) VALUES (?, ?, ?)", [filename, user, fecha], function(err) {
    if (err) {
      console.error("Error al guardar foto:", err);
      return res.status(500).json({ success: false, message: "Error al guardar la foto" });
    }
    res.json({ success: true, message: "Foto subida exitosamente" });
  });
});

app.get("/fotos", (req, res) => {
  db.all("SELECT id, filename, user FROM fotos ORDER BY id DESC", [], (err, rows) => {
    if (err) {
      console.error("Error al obtener fotos:", err);
      return res.json([]);
    }
    
    const resultado = rows.map(f => ({
      id: f.id,
      src: "/uploads/" + f.filename,
      user: f.user,
      puedeBorrar: f.user === req.session.user
    }));
    res.json(resultado);
  });
});

app.post("/borrar-foto", (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false, message: "No autorizado" });
  
  const { id } = req.body;
  
  if (!id) {
    return res.status(400).json({ success: false, message: "ID de foto requerido" });
  }

  db.get("SELECT filename, user FROM fotos WHERE id = ?", [id], (err, row) => {
    if (err) {
      console.error("Error al buscar foto:", err);
      return res.status(500).json({ success: false, message: "Error del servidor" });
    }
    
    if (!row) {
      return res.status(404).json({ success: false, message: "Foto no encontrada" });
    }
    
    if (row.user !== req.session.user) {
      return res.status(403).json({ success: false, message: "No tienes permiso para borrar esta foto" });
    }

    const filePath = path.join(__dirname, "public/uploads", row.filename);
    
    // Borrar archivo del sistema de archivos
    fs.unlink(filePath, (unlinkErr) => {
      // Continuar aunque el archivo no exista físicamente
      if (unlinkErr) {
        console.warn("Archivo no encontrado en el sistema:", unlinkErr.message);
      }
      
      // Borrar registro de la base de datos
      db.run("DELETE FROM fotos WHERE id = ?", [id], function(deleteErr) {
        if (deleteErr) {
          console.error("Error al borrar foto de la BD:", deleteErr);
          return res.status(500).json({ success: false, message: "Error al borrar la foto" });
        }
        res.json({ success: true, message: "Foto borrada exitosamente" });
      });
    });
  });
});

// Ruta de logout (opcional)
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, message: "Error al cerrar sesión" });
    }
    res.json({ success: true, message: "Sesión cerrada exitosamente" });
  });
});

// Ruta de salud para verificar que el servidor funciona
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

// Manejo de errores 404
app.use((req, res) => {
  res.status(404).json({ error: "Ruta no encontrada" });
});

// Manejo de errores generales
app.use((err, req, res, next) => {
  console.error("Error del servidor:", err);
  res.status(500).json({ error: "Error interno del servidor" });
});

// Configuración del puerto para Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
