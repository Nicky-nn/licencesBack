import express, { Express } from 'express';
import { createServer } from 'http';
import { ApolloServer } from 'apollo-server-express';
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/lib/use/ws';
import { makeExecutableSchema } from '@graphql-tools/schema';
import { PubSub } from 'graphql-subscriptions';
import {
  typeDefs,
  resolvers,
  authDirectiveTypeDefs,
  authDirectiveTransformer,
} from '../graphql';
import { getDb } from './database';
import { verifyToken } from '../utils/verifyToken';

export const configureServer = async () => {
  const app: Express = express();

  // Importar los módulos de graphql-upload dinámicamente
  const [{ default: GraphQLUpload }, { default: graphqlUploadExpress }] =
    await Promise.all([
      import('graphql-upload/GraphQLUpload.mjs'),
      import('graphql-upload/graphqlUploadExpress.mjs'),
    ]);

  // Configurar middleware de upload
  app.use(
    graphqlUploadExpress({
      maxFileSize: 1024 * 1024 * 1024, // 1GB
      maxFiles: 20, // 20 archivos
    }),
  );

  const httpServer = createServer(app); // Crear servidor HTTP
  const pubsub = new PubSub(); // Crear instancia de PubSub

  // Agregar Upload scalar a los resolvers
  const resolversWithUpload = {
    ...resolvers,
    Upload: GraphQLUpload,
  }; // Agregar Upload scalar a los resolvers

  const schema = authDirectiveTransformer(
    makeExecutableSchema({
      typeDefs: [typeDefs, authDirectiveTypeDefs],
      resolvers: resolversWithUpload,
    }),
  ); // Crear el esquema de GraphQL

  const apolloServer = new ApolloServer({
    schema,
    context: ({ req }) => ({
      db: getDb(),
      token: req.headers.authorization,
      pubsub,
    }),
  }); // Crear instancia de ApolloServer

  await apolloServer.start();
  apolloServer.applyMiddleware({ app, path: '/graphql' });

  const wsServer = new WebSocketServer({
    server: httpServer,
    path: '/graphql',
  });

  const serverCleanup = useServer(
    {
      schema,
      context: async (ctx) => {
        const token =
          ctx.connectionParams?.Authorization ||
          ctx.connectionParams?.authorization;
        let decodedToken;
        try {
          decodedToken = token ? verifyToken(token as string) : null;
        } catch (error) {
          console.error('Error al verificar el token:', error);
          throw new Error('Token inválido');
        }

        return {
          db: getDb(),
          token,
          decodedToken,
          pubsub,
        };
      },
      onError: (_ctx, message, errors) => {
        console.error('Error en WebSocket:', message, errors);
      },
    },
    wsServer,
  );

  wsServer.on('error', (error) => {
    console.error('Error en el servidor WebSocket:', error);
  });

  return { app, httpServer, apolloServer, wsServer, serverCleanup };
};
