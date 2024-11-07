// src/graphql/directives/auth.ts
import {
  GraphQLDirective,
  DirectiveLocation,
  GraphQLSchema,
  GraphQLField,
  defaultFieldResolver,
  GraphQLResolveInfo,
} from 'graphql';
import jwt from 'jsonwebtoken';
import { env } from '../../config';

interface AuthContext {
  token?: string;
  user?: any;
}

interface AuthArgs {
  [key: string]: any;
}

class AuthDirective extends GraphQLDirective {
  constructor() {
    super({
      name: 'auth',
      locations: [DirectiveLocation.FIELD_DEFINITION],
    });
  }

  visitFieldDefinition(field: GraphQLField<any, any>) {
    const { resolve = defaultFieldResolver } = field;
    field.resolve = async function (
      source: unknown,
      args: AuthArgs,
      context: AuthContext,
      info: GraphQLResolveInfo,
    ) {
      if (!context.token) {
        throw new Error('No se proporcionó token de autenticación');
      }
      try {
        const user = jwt.verify(context.token, env.JWT_SECRET);
        context.user = user;
      } catch (error) {
        throw new Error('Token inválido');
      }
      return resolve.call(this, source, args, context, info);
    };
  }
}

export const authDirective = (directiveName: string) => ({
  authDirectiveTypeDefs: `directive @${directiveName} on FIELD_DEFINITION`,
  authDirectiveTransformer: (schema: GraphQLSchema) => {
    const directive = new AuthDirective();
    const directives = [...schema.getDirectives(), directive];
    const newSchema = new GraphQLSchema({
      ...schema.toConfig(),
      directives,
    });
    return newSchema;
  },
});
