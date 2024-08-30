// user-repository.js
import DBLocal from 'db-local'
import { randomUUID } from 'crypto'
import bcrypt from 'bcrypt'
import { validateUsername, validatePassword, validateUserExists, validatePasswordMatch } from './validations.js' // Importa las funciones de validación

const { Schema } = new DBLocal({ path: './db' }) // Inicializa la base de datos en la ruta especificada

export const User = Schema('user', { // Define un esquema para la colección de usuarios
  _id: { type: String, required: true },
  username: { type: String, required: true, unique: true }, // username debe ser único
  password: { type: String, required: true }
})

export class UserRepository { // Define la clase UserRepository
  static async create ({ username, password }) {
    // Validaciones del username y password
    validateUsername(username)
    validatePassword(password)

    // Verificar si el nombre de usuario ya existe
    const existingUser = User.findOne({ username })
    if (existingUser) {
      throw new Error('El nombre de usuario ya está en uso')
    }

    // Generar un ID único para el nuevo usuario
    const _id = randomUUID() // Genera un UUID único para el usuario

    // Hashear la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10) // Hashea la contraseña con un salt de 10 rondas

    // Crear el nuevo usuario en la base de datos y guardar
    const newUser = User.create({ _id, username, password: hashedPassword }).save()

    // Devolver solo información pública del usuario
    return { _id: newUser._id, username: newUser.username }
  }

  static async login ({ username, password }) {
    // Validaciones del username y password
    validateUsername(username)
    validatePassword(password)

    // 1. Verificar si el usuario existe
    const user = validateUserExists(username)

    // 2. Comparar la contraseña proporcionada con el hash almacenado
    await validatePasswordMatch(password, user.password)

    // Devolver solo información pública del usuario
    return { _id: user._id, username: user.username }
  }
}
