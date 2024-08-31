// user-repository.js
import DBLocal from 'db-local'
import { randomUUID } from 'crypto'
import bcrypt from 'bcrypt'
import { validateUsername, validatePassword, validateUserExists, validatePasswordMatch } from './validations.js'

const { Schema } = new DBLocal({ path: './db' })

export const User = Schema('user', {
  _id: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    // Este método se mantiene igual para compatibilidad
    return this.register({ username, password })
  }

  static async register ({ username, password }) {
    validateUsername(username)
    validatePassword(password)

    const existingUser = User.findOne({ username })
    if (existingUser) {
      throw new Error('El nombre de usuario ya está en uso')
    }

    const _id = randomUUID()
    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = User.create({ _id, username, password: hashedPassword }).save()

    return { id: newUser._id, username: newUser.username }
  }

  static async login ({ username, password }) {
    validateUsername(username)
    validatePassword(password)

    const user = validateUserExists(username)
    await validatePasswordMatch(password, user.password)

    return { id: user._id, username: user.username }
  }
}
