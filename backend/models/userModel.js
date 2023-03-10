import mongoose from 'mongoose'
import { encrypter } from '../utils.js' 

const { Schema, model } = mongoose

mongoose.set('strictQuery', true)

const userSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, uppercase: true },
    publicAddress: { type: String, required: false, unique: true },
    passphrase: { type: Array, default: () => encrypter() },
    // telegramID: { type: Number, required: true, unique: true },
    telegramID: { type: Number, required: false, unique: true },
    telegramName: { type: String, required: false },
    telegramUsername : { type: String, required: false },
    telegramLink: { type: String, required: false, default: "no_link" },
    // telegramPhone: { type: Number, required: true, unique: true },
    telegramPhone: { type: Number, required: false, unique: true },
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
    roles: { type: string, required: true, default: roles.User  },
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

const roles = { "Admin": "Admin",
                "Artist": "Artist",
                "Farmer": "Farmer", 
                "User" : "User", 
              }

const User = mongoose.model('User', userSchema);

export default User;
