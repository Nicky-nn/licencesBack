import { IResolvers } from '@graphql-tools/utils';
import { ObjectId } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../../config/env';
import { generateOTP, verifyOTP, saveOTP } from '../../services/otp';
import { sendWhatsAppMessage } from '../../services/whatsapp';

interface JwtPayload {
  id: string;
  rol: string;
}
interface QueryParams {
  telefono?: string;
  nombre?: string;
  apellido?: string;
  correo?: string;
}

const verifyToken = (token: string): JwtPayload => {
  if (!token) {
    throw new Error('Token no proporcionado');
  }

  try {
    return jwt.verify(token.split(' ')[1], env.JWT_SECRET) as JwtPayload;
  } catch (error) {
    throw new Error('Token inválido');
  }
};

const userResolvers: IResolvers = {
  Usuario: {
    id: (parent) => parent._id.toString(),
    empresa: async (parent, _, { db }) => {
      if (parent.empresaId) {
        try {
          const objectId = new ObjectId(parent.empresaId);
          const empresa = await db
            .collection('empresas')
            .findOne({ _id: objectId });
          return empresa ? { ...empresa, id: empresa._id.toString() } : null;
        } catch (error) {
          console.error('Invalid empresaId:', parent.empresaId);
          return null;
        }
      }
      return null;
    },
  },
  Query: {
    obtenerUsuarios: async (
      _: any,
      { query }: { query?: QueryParams },
      { db, token }: { db: any; token: string },
    ): Promise<any[]> => {
      const decodedToken = verifyToken(token);

      const dbQuery: any = {};

      // Si se proporciona una consulta, construirla basada en los parámetros proporcionados
      if (query) {
        Object.entries(query).forEach(([key, value]) => {
          if (value && value.length >= 3) {
            dbQuery[key] = new RegExp(value, 'i');
          }
        });
      }

      if (decodedToken.rol === 'SUPER_ADMIN') {
        return await db.collection('usuarios').find(dbQuery).toArray();
      } else if (decodedToken.rol === 'ADMIN') {
        return await db
          .collection('usuarios')
          .find({
            $and: [
              dbQuery,
              {
                $or: [
                  { usuCre: decodedToken.id },
                  { _id: new ObjectId(decodedToken.id) },
                ],
              },
            ],
          })
          .toArray();
      } else {
        return await db
          .collection('usuarios')
          .find({
            ...dbQuery,
            _id: new ObjectId(decodedToken.id),
          })
          .toArray();
      }
    },
    listarUsuarios: async (_, __, { db, token }) => {
      const decodedToken = verifyToken(token);

      if (decodedToken.rol === 'SUPER_ADMIN') {
        return await db.collection('usuarios').find().toArray();
      } else if (decodedToken.rol === 'ADMIN') {
        return await db
          .collection('usuarios')
          .find({
            $or: [
              { usuCre: decodedToken.id },
              { _id: new ObjectId(decodedToken.id) },
            ],
          })
          .toArray();
      } else {
        return await db
          .collection('usuarios')
          .find({ _id: new ObjectId(decodedToken.id) })
          .toArray();
      }
    },
    me: async (_, __, { db, token }) => {
      const decodedToken = verifyToken(token);
      return await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(decodedToken.id) });
    },
  },
  Mutation: {
    login: async (_, { email, password }, { db }) => {
      const usuario = await db.collection('usuarios').findOne({ email });
      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }
      if (usuario.estado !== 'ACTIVO') {
        throw new Error('Usuario inactivo');
      }
      const isValid = await bcrypt.compare(password, usuario.password);
      if (!isValid) {
        throw new Error('Contraseña incorrecta');
      }
      const token = jwt.sign(
        { id: usuario._id, rol: usuario.rol },
        env.JWT_SECRET,
        { expiresIn: '1d' },
      );
      return { token, usuario };
    },
    crearUsuarioNormal: async (_, { input }, { db, token }) => {
      const decodedToken = verifyToken(token);

      if (decodedToken.rol !== 'ADMIN' && decodedToken.rol !== 'SUPER_ADMIN') {
        throw new Error('No tienes permisos para crear usuarios');
      }

      // Generar identificador único de número de teléfono
      let identificadorTelefono;
      let isUnique = false;
      while (!isUnique) {
        identificadorTelefono = Math.floor(Math.random() * 1000000000000000)
          .toString()
          .padStart(15, '0');
        const existingIdentificador = await db
          .collection('usuarios')
          .findOne({ identificadorTelefono });
        if (!existingIdentificador) {
          isUnique = true;
        }
      }

      // Validar email único solo para los usuarios del admin actual
      const existingUser = await db.collection('usuarios').findOne({
        email: input.email,
        usuCre: decodedToken.id,
      });
      if (existingUser) {
        throw new Error(
          'Ya existe un usuario con este correo electrónico en tú grupo',
        );
      }

      const hashedPassword = await bcrypt.hash(input.password, 10);
      const usuario = {
        ...input,
        password: hashedPassword,
        rol: 'NORMAL',
        estado: 'INACTIVO',
        identificadorTelefono,
        usuCre: decodedToken.id,
        fechaCre: new Date(),
        usuMod: decodedToken.id,
        fechaMod: new Date(),
      };

      const result = await db.collection('usuarios').insertOne(usuario);
      return { ...usuario, id: result.insertedId };
    },
    crearAdmin: async (_, { input }, { db }) => {
      const existingUser = await db.collection('usuarios').findOne({
        $or: [{ email: input.email }, { telefono: input.telefono }],
      });

      if (existingUser && existingUser.estado === 'ACTIVO') {
        throw new Error(
          'Ya existe un usuario activo con este email o número de teléfono',
        );
      }

      if (existingUser && existingUser.estado === 'PENDIENTE') {
        const otp = generateOTP();
        await saveOTP(input.telefono, otp);

        try {
          await sendWhatsAppMessage(input.telefono, otp, otp.toString());
        } catch (error) {
          console.error('Error al enviar OTP por WhatsApp:', error);
          throw new Error('No se pudo enviar el código de verificación');
        }

        return {
          success: true,
          message: 'Se ha reenviado un nuevo código de verificación',
          usuario: existingUser,
        };
      }

      const otp = generateOTP();
      await saveOTP(input.telefono, otp);

      try {
        await sendWhatsAppMessage(input.telefono, otp, otp.toString());
      } catch (error) {
        console.error('Error al enviar OTP por WhatsApp:', error);
        throw new Error('No se pudo enviar el código de verificación');
      }

      const hashedPassword = await bcrypt.hash(input.password, 10);
      const usuario = {
        ...input,
        password: hashedPassword,
        rol: 'ADMIN',
        estado: 'PENDIENTE',
        fechaCre: new Date(),
        fechaMod: new Date(),
      };

      const result = await db.collection('usuarios').insertOne(usuario);
      const createdUser = { ...usuario, id: result.insertedId };

      return {
        success: true,
        message: 'Se ha creado el usuario y enviado el código de verificación',
        usuario: createdUser,
      };
    },
    verificarOTP: async (_, { nombre, telefono, otp }, { db }) => {
      const usuario = await db
        .collection('usuarios')
        .findOne({ nombre, telefono });
      if (!usuario) {
        return {
          success: false,
          message:
            'No se encontró un usuario con el nombre y teléfono proporcionados',
          usuario: null,
        };
      }
      if (usuario.estado === 'ACTIVO') {
        return {
          success: false,
          message: 'Usuario ya activo',
          usuario: null,
        };
      }

      const isValidOTP = await verifyOTP(telefono, otp);
      if (!isValidOTP) {
        return {
          success: false,
          message: 'OTP inválido',
          usuario: null,
        };
      }

      await db
        .collection('usuarios')
        .updateOne(
          { _id: usuario._id },
          { $set: { estado: 'ACTIVO', fechaMod: new Date() } },
        );

      const updatedUser = { ...usuario, estado: 'ACTIVO' };

      return {
        success: true,
        message: 'OTP verificado correctamente',
        usuario: updatedUser,
      };
    },
    toggleUsuario: async (_, { id }, { db, token }) => {
      const decodedToken = verifyToken(token);

      let usuario;
      if (decodedToken.rol === 'SUPER_ADMIN') {
        usuario = await db
          .collection('usuarios')
          .findOne({ _id: new ObjectId(id) });
      } else if (decodedToken.rol === 'ADMIN') {
        usuario = await db.collection('usuarios').findOne({
          _id: new ObjectId(id),
          usuCre: decodedToken.id,
        });
      }

      if (!usuario) {
        throw new Error(
          'No tienes permiso para modificar este usuario o el usuario no existe',
        );
      }

      const nuevoEstado = usuario.estado === 'ACTIVO' ? 'INACTIVO' : 'ACTIVO';

      const result = await db.collection('usuarios').updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            estado: nuevoEstado,
            usuMod: decodedToken.id,
            fechaMod: new Date(),
          },
        },
      );

      if (result.modifiedCount === 0) {
        throw new Error('No se pudo cambiar el estado del usuario');
      }

      return await db.collection('usuarios').findOne({ _id: new ObjectId(id) });
    },
    actualizarUsuario: async (_, { id, input }, { db, token }) => {
      const decodedToken = verifyToken(token);

      let usuarioAActualizar;
      if (decodedToken.rol === 'SUPER_ADMIN') {
        usuarioAActualizar = await db
          .collection('usuarios')
          .findOne({ _id: new ObjectId(id) });
      } else if (decodedToken.rol === 'ADMIN') {
        usuarioAActualizar = await db.collection('usuarios').findOne({
          _id: new ObjectId(id),
          $or: [
            { usuCre: decodedToken.id },
            { _id: new ObjectId(decodedToken.id) },
          ],
        });
      } else {
        usuarioAActualizar = await db
          .collection('usuarios')
          .findOne({ _id: new ObjectId(decodedToken.id) });
      }

      if (!usuarioAActualizar) {
        throw new Error(
          'No tienes permiso para actualizar este usuario o el usuario no existe',
        );
      }

      if (input.password) {
        input.password = await bcrypt.hash(input.password, 10);
      }

      const result = await db.collection('usuarios').updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            ...input,
            usuMod: decodedToken.id,
            fechaMod: new Date(),
          },
        },
      );

      if (result.modifiedCount === 0) {
        throw new Error('No se pudo actualizar el usuario');
      }

      return await db.collection('usuarios').findOne({ _id: new ObjectId(id) });
    },
    eliminarUsuario: async (_, { id }, { db, token }) => {
      const decodedToken = verifyToken(token);

      let usuarioAEliminar;
      if (decodedToken.rol === 'SUPER_ADMIN') {
        usuarioAEliminar = await db
          .collection('usuarios')
          .findOne({ _id: new ObjectId(id) });
      } else if (decodedToken.rol === 'ADMIN') {
        usuarioAEliminar = await db.collection('usuarios').findOne({
          _id: new ObjectId(id),
          usuCre: decodedToken.id,
        });
      }

      if (!usuarioAEliminar) {
        throw new Error(
          'No tienes permiso para eliminar este usuario o el usuario no existe',
        );
      }

      const result = await db
        .collection('usuarios')
        .deleteOne({ _id: new ObjectId(id) });

      if (result.deletedCount === 0) {
        throw new Error('No se pudo eliminar el usuario');
      }

      return true;
    },
    actualizarAdmin: async (_, { input }, { db, token }) => {
      const decodedToken = verifyToken(token);

      if (decodedToken.rol !== 'ADMIN') {
        throw new Error(
          'No tienes permisos para actualizar información de administrador',
        );
      }

      const { empresaId, ...updateData } = input;

      // Verificar si la empresa existe
      let empresa = null;
      if (empresaId) {
        empresa = await db
          .collection('empresas')
          .findOne({ _id: new ObjectId(empresaId) });
        if (!empresa) {
          throw new Error('La empresa especificada no existe');
        }
      }

      // Actualizar el usuario
      const result = await db.collection('usuarios').updateOne(
        { _id: new ObjectId(decodedToken.id) },
        {
          $set: {
            ...updateData,
            empresaId: empresaId ? new ObjectId(empresaId) : null,
            usuMod: decodedToken.id,
            fechaMod: new Date(),
          },
        },
      );

      if (result.modifiedCount === 0) {
        throw new Error(
          'No se pudo actualizar la información del administrador',
        );
      }

      // Obtener el usuario actualizado
      const updatedUser = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(decodedToken.id) });

      // Si hay una empresa asociada, incluirla en la respuesta
      if (empresa) {
        updatedUser.empresa = { ...empresa, id: empresa._id.toString() };
      }

      return {
        success: true,
        message: 'Información del administrador actualizada correctamente',
        usuario: updatedUser,
      };
    },
  },
};

export default userResolvers;
