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
  const httpServer = createServer(app);

  const pubsub = new PubSub();

  const schema = authDirectiveTransformer(
    makeExecutableSchema({
      typeDefs: [typeDefs, authDirectiveTypeDefs],
      resolvers,
    }),
  );

  const apolloServer = new ApolloServer({
    schema,
    context: ({ req }) => ({
      db: getDb(),
      token: req.headers.authorization,
      pubsub,
    }),
  });

  await apolloServer.start();
  apolloServer.applyMiddleware({ app, path: '/graphql' });

  // Configuración para graphql-ws
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
