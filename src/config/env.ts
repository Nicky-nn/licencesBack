// src/config/env.ts
import dotenv from 'dotenv';
import { cleanEnv, str, port } from 'envalid';

// Cargar variables de entorno desde el archivo .env
dotenv.config();

// Validar y limpiar las variables de entorno
export const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ['development', 'test', 'production'] }),
  PORT: port({ default: 3000 }),
  MONGODB_URI: str(),
  DB_NAME: str({ default: 'your_database' }),
  JWT_SECRET: str(),
  OTP_SECRET: str(),
  WHATSAPP_API_KEY: str(),
  REDIS_URL: str(),
});
