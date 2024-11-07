// src/config/security.ts
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';
import { Express } from 'express';

export const configureSecurity = (app: Express) => {
  // Rate limiting
  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100 // limite de 100 solicitudes por ventana
  });

  // Aplicar rate limiting a todas las solicitudes
  app.use(limiter);

  // Configurar CORS
  app.use(cors());

  // Usar Helmet para configurar varios encabezados HTTP relacionados con la seguridad
  app.use(helmet());
};