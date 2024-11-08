import {
  connectDatabase,
  closeDatabase,
  configureServer,
  env,
  configureSecurity,
} from './config';
import { Express } from 'express';

// In your Express app setup

async function startServer() {
  try {
    await connectDatabase();
    const { app, httpServer } = await configureServer();

    configureSecurity(app as Express);

    httpServer.listen(env.PORT, () => {
      createBoxedMessage(
        `🚀 Servidor GraphQL Corriendo: http://localhost:${env.PORT}/graphql`,
        [`🔌 Suscripciones WebSocket: ws://localhost:${env.PORT}/graphql`],
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
  createBoxedMessage(
    '🔔 Señal SIGTERM recibida. Cerrando el servidor HTTP y la conexión a la base de datos.',
    [],
  );
  await closeDatabase();
  process.exit(0);
});

export const createBoxedMessage = (title: string, messages: any[]) => {
  const width =
    Math.max(
      ...messages.map((msg: string | any[]) => msg.length),
      title.length,
    ) + 4; // Ancho de la caja ajustable
  const horizontalLine = '─'.repeat(width);

  console.log(`┌${horizontalLine}┐`);
  console.log(`│ ${title.padEnd(width - 2)} │`);
  console.log(`├${horizontalLine}┤`);

  messages.forEach((message: string) => {
    console.log(`│ ${message.padEnd(width - 2)} │`);
  });

  console.log(`└${horizontalLine}┘`);
};
