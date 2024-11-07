// src/graphql/index.ts
import { mergeTypeDefs, mergeResolvers } from '@graphql-tools/merge';
import { loadFilesSync } from '@graphql-tools/load-files';
import path from 'path';
import { authDirective } from './directives/auth';

// Cargar todos los archivos de schema
const typesArray = loadFilesSync(path.join(__dirname, './schema'));

// Cargar todos los archivos de resolvers
const resolversArray = loadFilesSync(path.join(__dirname, './resolvers'));

// Combinar todos los schemas
export const typeDefs = mergeTypeDefs(typesArray);

// Combinar todos los resolvers
export const resolvers = mergeResolvers(resolversArray);

const { authDirectiveTypeDefs, authDirectiveTransformer } =
  authDirective('auth');

export { authDirectiveTypeDefs, authDirectiveTransformer };
