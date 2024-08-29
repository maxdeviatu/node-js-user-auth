import express from 'express'
import { config } from './config.js'
import { UserRepository } from './user-repository.js' // Importa UserRepository para manejar usuarios

const app = express()
const port = config.port

// Middleware para parsear cuerpos de solicitudes JSON
app.use(express.json()) // Permite que el servidor maneje datos JSON en el cuerpo de las solicitudes

// Ruta raíz
app.get('/', (req, res) => {
  res.send('¡Hola, mundo!') // Responde con un mensaje simple en la ruta raíz
})

// Ruta para inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body // Obtiene username y password del cuerpo de la solicitud

  try {
    const user = await UserRepository.login({ username, password }) // Intenta iniciar sesión con las credenciales
    res.status(200).json(user) // Responde con los detalles del usuario autenticado
  } catch (error) {
    console.error('Error al iniciar sesión:', error.message)

    // Manejar errores específicos para proporcionar feedback detallado
    if (error.message === 'Usuario no encontrado') {
      res.status(404).json({ error: 'Usuario no encontrado' })
    } else if (error.message === 'Contraseña incorrecta') {
      res.status(401).json({ error: 'Contraseña incorrecta' })
    } else {
      res.status(400).json({ error: 'Credenciales inválidas' })
    }
  }
})

// Ruta para registro de usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body // Obtiene username y password del cuerpo de la solicitud

  try {
    const newUser = await UserRepository.create({ username, password }) // Crea un nuevo usuario
    res.status(201).json(newUser) // Responde con el usuario creado y estado 201 (Creado)
  } catch (error) {
    console.error('Error al registrar usuario:', error.message)
    res.status(400).json({ error: error.message }) // Responde con un error si la creación falla
  }
})

// Ruta para cierre de sesión (pendiente de implementación)
app.post('/logout', (req, res) => {
  // Lógica para manejar el cierre de sesión
  res.status(200).send('Sesión cerrada correctamente')
})

// Ruta protegida (pendiente de implementación)
app.get('/protected', (req, res) => {
  // Lógica para manejar el acceso a contenido protegido
  res.status(401).send('No autorizado')
})

// Inicia el servidor y escucha en el puerto especificado
app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${port}`)
})
