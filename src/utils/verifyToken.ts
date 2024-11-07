import { JwtPayload } from 'jsonwebtoken';
import { env } from '../config/env';
import jwt from 'jsonwebtoken';

export const verifyToken = (token: string): JwtPayload => {
  if (!token) {
    throw new Error('Token no proporcionado');
  }

  try {
    return jwt.verify(token.split(' ')[1], env.JWT_SECRET) as JwtPayload;
  } catch (error) {
    throw new Error('Token inválido');
  }
};
