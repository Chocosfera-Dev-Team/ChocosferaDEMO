import mongoose from 'mongoose'
import { Schema, model } from mongoose
import bip39 from 'bip39'
import crypto from 'crypto'
// import { create } from './Schemas/User'

mongoose.set('strictQuery', true)

const UserSchema = new Schema(
  {
    publicAddress: { type: String, required: true, unique: true },
    passphrase: { type: Array, default: () => createEncryptedPassPhrase() },
    telegramID: { type: Number, required: true, unique: true },
    telegramName: { type: String, required: false },
    telegramUsername : { type: String, required: false },
    telegramLink: { type: String, required: false, default: "no_link" },
    telegramPhone: { type: Number, required: true, unique: true },
    telegramVerifiedPhone: { type: Boolean, default: false },
    telegramVerifiedEmail: { type: Boolean, default: false },
    telegramReferer: { type: Number, required: false },
    emailCode: { type: Number, required: false },
    phoneCode: { type: Number, required: false },
    name: { type: String, required: false },
    surname: { type: String, required: false },
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    recoveryPasswordId: { type: String, require: false, default: ''},
    language: { type: String, required: false },
    refereeNumber: { type: Number, required: true, default: 0 },
    listXeBook: { type: Array, required: true, default: 0 },
    isClient: { type: Boolean, required: true, default: false },
    birthday: { type: String, required: false },
    gender: { type: String, enum:["M", "F"], required: false },
    city: { type: String, required: false, uppercase: true },
    country: { type: String, required: false },
    isAdmin: { type: Boolean, default: false, required: true },
    isSeller: { type: Boolean, default: true, required: true },
    hasAd: { type: Boolean, default: false, required: true },
    activity: { type: Number, default: 0, require: false },
    inscriptionBlock: { type: Number, required: true, default: 0 },
    verify: {
      verified: { type: Boolean, default: false },
      trusted_link: { type: String, required: false }
    }
  },
  {
    timestamps: true,
  }
)

const createEncryptedPassPhrase = () => {
  require('dotenv').config()
  const passphrase = bip39.generateMnemonic()
  const encryptionKey = process.env.ENCRYPTION_KEY // Get from crypto.randomBytes(32)
  const iv = process.env.IV // Get from crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv)
  let encrypted = cipher.update(passphrase, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  console.log(`Passphrase: ${passphrase}`)
  console.log(`Encrypted passphrase: ${encrypted}`)
  console.log(`Encryption key: ${encryptionKey.toString('hex')}`)
  console.log(`IV: ${iv.toString('hex')}`)


  // TODO: Use in user wallet as a function
  /*
  const encrypted = '...'; // Replace with your actual encrypted passphrase
  const encryptionKeyBuff = Buffer.from( encryptionKey, 'hex' ); // Replace with your actual encryption key
  const iv2 = Buffer.from( iv, 'hex' ); // Replace with your actual IV

  // Create a decipher using AES-256-CBC algorithm
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, iv)

  // Decrypt the encrypted passphrase using the decipher
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8')

  console.log(`Decrypted passphrase: ${decrypted}`)
  */
}

const User = mongoose.model('User', userSchema);

export default User;
