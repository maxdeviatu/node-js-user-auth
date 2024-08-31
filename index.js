// Importación de módulos necesarios
import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser' // Manejo de cookies
import jwt from 'jsonwebtoken' // Creación y verificación de tokens JWT
import dotenv from 'dotenv' // Manejo de variables de entorno
import path from 'path' // Manejo de rutas de archivos
import { fileURLToPath } from 'url' // Obtener la ruta actual del archivo
import { config } from './config.js' // Configuración personalizada (puerto)
import { UserRepository } from './user-repository.js' // Gestión de usuarios
import morgan from 'morgan' // Middleware para logging de solicitudes HTTP

// Cargar variables de entorno desde el archivo .env
dotenv.config()

// Configuración inicial de Express
const app = express()
const port = config.port
const __filename = fileURLToPath(import.meta.url) // Obtener el nombre de archivo actual
const __dirname = path.dirname(__filename) // Obtener el directorio del archivo actual

// Configuración del motor de plantillas y rutas de vistas
app.set('view engine', 'ejs') // Usar EJS como motor de plantillas
app.set('views', path.join(__dirname, 'views')) // Ubicación de las vistas

// Configuración de CORS para permitir solicitudes desde un origen específico
const corsOptions = {
  origin: 'https://socketidea.webflow.io', // Origen permitido
  methods: ['GET', 'POST', 'OPTIONS'], // Métodos HTTP permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Encabezados permitidos
  credentials: true, // Permitir el envío de cookies y otras credenciales
  optionsSuccessStatus: 200 // Estado exitoso para solicitudes OPTIONS
}

// Uso de middlewares
app.use(morgan('dev')) // Logging de solicitudes HTTP
app.use(cors(corsOptions)) // Configuración de CORS
app.use(cookieParser()) // Manejo de cookies
app.use(express.json()) // Parseo de JSON en solicitudes
app.use(express.urlencoded({ extended: true })) // Parseo de datos de formularios

// Middleware de autenticación: Verifica la presencia y validez de un token JWT
const authMiddleware = (req, res, next) => {
  console.log('Verificando autenticación...')
  const token = req.cookies.auth_token // Obtener el token de las cookies

  if (!token) {
    console.log('No se encontró token en las cookies.')
    return res.redirect('/') // Redirigir a la página de inicio de sesión
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET) // Verificar y decodificar el token
    req.user = decoded // Guardar la información del usuario en la solicitud
    console.log('Token válido, usuario autenticado:', req.user)
    next() // Continuar con la siguiente función
  } catch (error) {
    console.log('Error al verificar el token:', error.message)
    res.redirect('/') // Redirigir a la página de inicio de sesión en caso de error de verificación
  }
}

// Ruta principal: Verifica si el usuario está autenticado y muestra el panel o el formulario de login
app.get('/', (req, res) => {
  const token = req.cookies.auth_token // Obtener el token de las cookies
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET) // Verificar y decodificar el token
      console.log('Token válido en ruta raíz, usuario:', decoded.username)
      res.render('index', { username: decoded.username }) // Renderizar vista con el nombre de usuario
    } catch (error) {
      console.log('Token inválido en ruta raíz:', error.message)
      res.render('index', { username: null }) // Renderizar vista sin usuario
    }
  } else {
    console.log('No se encontró token en ruta raíz.')
    res.render('index', { username: null }) // Renderizar vista sin usuario
  }
})

// Ruta de inicio de sesión: Autentica al usuario y establece una cookie con un token JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body
  console.log('Intentando iniciar sesión con username:', username)
  try {
    const user = await UserRepository.login({ username, password }) // Autenticar usuario
    console.log('Usuario encontrado:', user.username)
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' }) // Crear token JWT
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Ajuste de sameSite para manejo de cookies
      maxAge: 3600000
    })
    console.log('Token generado y cookie establecida.')
    res.json({ success: true, username: user.username, redirect: '/protected' }) // Agregar redirección a la respuesta
  } catch (error) {
    console.error('Error al iniciar sesión:', error.message)
    res.status(401).json({ error: error.message || 'Credenciales inválidas' })
  }
})

// Ruta de registro: Registra un nuevo usuario y establece una cookie con un token JWT
app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log('Intentando registrar usuario:', username)

  if (!username || !password) {
    return res.status(400).json({ error: 'Se requieren nombre de usuario y contraseña' })
  }

  try {
    const user = await UserRepository.register({ username, password }) // Registrar usuario
    console.log('Usuario registrado:', user.username)
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' }) // Crear token JWT
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Ajuste de sameSite para manejo de cookies
      maxAge: 3600000
    })
    console.log('Token generado y cookie establecida para el nuevo usuario.')
    res.json({ success: true, username: user.username }) // Responder con éxito
  } catch (error) {
    console.error('Error al registrar usuario:', error.message)
    res.status(400).json({ error: error.message || 'No se pudo registrar el usuario' })
  }
}) 

// Ruta de cierre de sesión: Elimina la cookie de autenticación
app.post('/logout', (req, res) => {
  console.log('Cerrando sesión, eliminando cookie de autenticación.')
  res.clearCookie('auth_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' // Ajuste de sameSite para manejo de cookies
  })
  res.json({ success: true }) // Responder con éxito
})

// Ruta protegida: Solo accesible para usuarios autenticados
app.get('/protected', authMiddleware, (req, res) => {
  res.render('protected', { user: req.user }) // Pasar los datos del usuario a la vista
})


// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`)
})
