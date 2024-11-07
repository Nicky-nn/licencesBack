// src/services/otp.ts
import crypto from 'crypto';
import { getDb } from '../config/database';

export const generateOTP = (): string => {
  return crypto.randomInt(100000, 999999).toString();
};

export const verifyOTP = async (
  telefono: string,
  otp: string,
): Promise<boolean> => {
  const db = getDb();

  const storedOTP = await db.collection('otps').findOne({
    telefono,
    otp,
    expiresAt: { $gt: new Date() },
  });

  if (storedOTP) {
    // Eliminar el OTP usado
    await db.collection('otps').deleteOne({ _id: storedOTP._id });
    return true;
  }

  return false;
};

export const saveOTP = async (telefono: string, otp: string): Promise<void> => {
  const db = getDb();
  await db.collection('otps').insertOne({
    telefono,
    otp,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutos de validez
  });
};
