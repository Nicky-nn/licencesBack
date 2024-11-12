import { MongoClient, Db, ObjectId } from 'mongodb';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import { Usuario } from '../utils/interfaces';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:1234';
const DB_NAME = process.env.DB_NAME || 'whatsapp_bot';

let client: MongoClient;
let db: Db;

export const connectDatabase = async (): Promise<void> => {
  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log('✅ MongoDB conectado');

    // Verificar si existe un SUPER_ADMIN
    const superAdmin = await db
      .collection('usuarios')
      .findOne({ rol: 'SUPER_ADMIN' });
    if (!superAdmin) {
      // Crear SUPER_ADMIN si no existe
      const hashedPassword = await bcrypt.hash(
        process.env.SUPER_ADMIN_PASSWORD || 'defaultpassword',
        10,
      );
      const newSuperAdmin = {
        id: new ObjectId().toHexString(),
        nombre: 'Super Admin',
        apellido: 'Bot',
        email: process.env.SUPER_ADMIN_EMAIL || 'admin@example.com',
        password: hashedPassword,
        telefono: process.env.SUPER_ADMIN_PHONE || '0000000000',
        rol: 'SUPER_ADMIN',
        estado: 'ACTIVO',
        creditos: 1000,
        empresas: [],
        productos: [],
      } as Usuario;
      await db.collection('usuarios').insertOne(newSuperAdmin);
      console.log('✅ SUPER_ADMIN creado');
    } else {
      console.log('✅ SUPER_ADMIN ya existe');
    }
  } catch (error) {
    console.error('❌ Error conectando a MongoDB:', error);
    process.exit(1);
  }
};

export const getDb = (): Db => {
  if (!db) {
    throw new Error('❌ Base de datos no inicializada');
  }
  return db;
};

export const closeDatabase = async (): Promise<void> => {
  if (client) {
    await client.close();
    console.log('❌ MongoDB desconectado');
  }
};
