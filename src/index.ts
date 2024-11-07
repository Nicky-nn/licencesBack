import {
  connectDatabase,
  closeDatabase,
  configureServer,
  env,
  configureSecurity,
} from './config';
import { Express } from 'express';

async function startServer() {
  try {
    await connectDatabase();
    const { app, httpServer } = await configureServer();

    configureSecurity(app as Express);

    httpServer.listen(env.PORT, () => {
      console.log(
        `🚀 Servidor GraphQL corriendo en http://localhost:${env.PORT}/graphql`,
      );
      console.log(
        `🔌 Suscripciones WebSocket disponibles en ws://localhost:${env.PORT}/graphql`,
      );
    });
  } catch (error) {
    console.error('❌ Error al iniciar el servidor:', error);
    await closeDatabase();
    process.exit(1);
  }
}

startServer();

process.on('SIGTERM', async () => {
  console.log(
    '🔔 Señal SIGTERM recibida. Cerrando el servidor HTTP y la conexión a la base de datos.',
  );
  await closeDatabase();
  process.exit(0);
});
