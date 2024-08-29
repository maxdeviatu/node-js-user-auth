// validations.js
import bcrypt from 'bcrypt'
import { User } from './user-repository.js' // Importa el esquema de User para verificar usuarios

/**
 * Valida que el username sea una cadena de texto válida y tenga al menos 3 caracteres.
 * @param {string} username - El nombre de usuario a validar.
 * @throws {Error} Si el nombre de usuario no es válido.
 */
export function validateUsername (username) {
  if (typeof username !== 'string') {
    throw new Error('El nombre de usuario debe ser una cadena de texto')
  }
  if (username.length < 3) {
    throw new Error('El nombre de usuario debe tener al menos 3 caracteres')
  }
}

/**
 * Valida que el password sea una cadena de texto válida y tenga al menos 6 caracteres.
 * @param {string} password - La contraseña a validar.
 * @throws {Error} Si la contraseña no es válida.
 */
export function validatePassword (password) {
  if (typeof password !== 'string') {
    throw new Error('La contraseña debe ser una cadena de texto')
  }
  if (password.length < 6) {
    throw new Error('La contraseña debe tener al menos 6 caracteres')
  }
}

/**
 * Verifica si un usuario existe en la base de datos.
 * @param {string} username - El nombre de usuario a buscar.
 * @returns {Object} El usuario encontrado.
 * @throws {Error} Si el usuario no se encuentra.
 */
export function validateUserExists (username) {
  const user = User.findOne({ username })
  if (!user) {
    throw new Error('Usuario no encontrado')
  }
  return user
}

/**
 * Compara la contraseña proporcionada con el hash almacenado del usuario.
 * @param {string} password - La contraseña proporcionada.
 * @param {string} hashedPassword - El hash almacenado del usuario.
 * @returns {boolean} Verdadero si la contraseña es válida, falso de lo contrario.
 * @throws {Error} Si la contraseña no es válida.
 */
export async function validatePasswordMatch (password, hashedPassword) {
  const isPasswordValid = await bcrypt.compare(password, hashedPassword)
  if (!isPasswordValid) {
    throw new Error('Contraseña incorrecta')
  }
  return isPasswordValid
}
