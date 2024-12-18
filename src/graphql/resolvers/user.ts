/* eslint-disable @typescript-eslint/no-unused-vars */
import { IResolvers } from '@graphql-tools/utils';
import { ObjectId } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { env } from '../../config/env';
import { generateOTP, verifyOTP, saveOTP } from '../../services/otp';
import { sendWhatsAppMessage } from '../../services/whatsapp';
import { PubSub, withFilter } from 'graphql-subscriptions';
import { createWriteStream } from 'fs';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

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

const NOTIFICACION_CHANNEL = 'NOTIFICACIONES';
const pubsub = new PubSub();

const generarHash = async (password: string) => {
  return await bcrypt.hash(password, 10);
};

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

export function parseQuery(query: string) {
  const queryObj: { $or?: { [key: string]: RegExp }[] } = {};
  const andConditions = query.split('&&'); // Dividir las condiciones por '&&' para aplicar AND

  andConditions.forEach((condition) => {
    const orConditions = condition.split('||'); // Dividir las condiciones por '||' para aplicar OR
    const orQuery: { [x: number]: RegExp }[] = [];

    orConditions.forEach((cond) => {
      const [key, value] = cond.split('=');
      if (key && value) {
        // Comprobar si la clave es válida. Aquí no limitamos las claves (trabajamos con cualquier clave)
        // Usamos RegExp para realizar búsquedas parciales y case insensitive
        orQuery.push({ [key]: new RegExp(value, 'i') });
      }
    });

    if (orQuery.length > 0) {
      queryObj['$or'] = orQuery; // Si hay condiciones OR, las aplicamos
    }
  });

  return queryObj;
}

const userResolvers: IResolvers = {
  Usuario: {
    id: (parent) => parent._id || parent.id,
  },
  Empresa: {
    _id: (parent) => parent._id.toString(),
  },
  Query: {
    me: async (_, __, { db, token }) => {
      // Decodificar el token para obtener el ID del usuario
      const decodedToken = verifyToken(token);

      // Buscar el usuario en la colección de usuarios
      const usuario = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(decodedToken.id) });

      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }

      // Buscar todas las empresas basándose en el array de empresas del usuario
      const empresas = await db
        .collection('empresas')
        .find({
          _id: { $in: usuario.empresas },
        })
        .toArray();

      // Mapear las empresas para asegurar que tengan la estructura correcta
      const empresasMapeadas = empresas.map(
        (empresa: {
          _id: { toString: () => any };
          nombre: string;
          correo: string;
          direccion: string;
          urlImagen: any;
          usuarios: any[];
          productos: any;
          createdAt: any;
          updatedAt: any;
          usucreAt: any;
          usuactAt: any;
        }) => ({
          _id: empresa._id.toString(),
          nombre: empresa.nombre,
          correo: empresa.correo,
          direccion: empresa.direccion,
          urlImagen: empresa.urlImagen,
          usuarios:
            empresa.usuarios?.map(
              (u: { usuario: { toString: () => any }; cargo: any }) => ({
                usuario: u.usuario.toString(),
                cargo: u.cargo,
              }),
            ) || [],
          productos: empresa.productos || [],
          createdAt: empresa.createdAt,
          updatedAt: empresa.updatedAt,
          usucreAt: empresa.usucreAt,
          usuactAt: empresa.usuactAt,
        }),
      );

      // Crear el objeto de retorno que coincida con el schema
      return {
        id: usuario._id.toString(),
        urlImagen: usuario.urlImagen,
        nombre: usuario.nombre,
        apellido: usuario.apellido,
        email: usuario.email,
        password: usuario.password,
        telefono: usuario.telefono,
        rol: usuario.rol,
        estado: usuario.estado,
        creditos: usuario.creditos,
        empresas: empresasMapeadas,
        productos: usuario.productos || [],
      };
    },
    listarAdministradores: async (
      _,
      { page = 1, limit = 20, query = '', reverse = false },
      { db },
    ) => {
      const skip = (page - 1) * limit;
      let filter = { rol: 'ADMIN' }; // Filtro por rol 'ADMIN' por defecto

      // Si hay una consulta (query), la procesamos
      if (query) {
        const queryObj = parseQuery(query); // Parseamos la búsqueda dinámica
        filter = { ...filter, ...queryObj };
      }

      // Obtener los administradores con la paginación y el filtro de búsqueda
      const admins = await db
        .collection('usuarios')
        .find(filter)
        .skip(skip)
        .limit(limit)
        .sort({ id: reverse ? -1 : 1 }) // Aplicamos orden inverso si 'reverse' es true
        .toArray();

      if (!admins || admins.length === 0) {
        throw new Error('No hay administradores');
      }

      return admins;
    },

    obtenerAdministrador: async (_, { id }, { db }) => {
      const th = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(id), rol: 'ADMIN' });
      if (!th) {
        throw new Error('Administrador no encontrado');
      }
      return th;
    },

    // listar empresas segun el suuario
    listarEmpresas: async (
      _,
      { page = 1, limit = 20, query = '', reverse = false },
      { db, token },
    ) => {
      const decodedToken = verifyToken(token);
      const skip = (page - 1) * limit;
      let filter = { rol: 'EMPRESA', id: decodedToken.id }; // Filtro por rol 'EMPRESA' por defecto

      // Si hay una consulta (query), la procesamos
      if (query) {
        const queryObj = parseQuery(query); // Parseamos la búsqueda dinámica
        filter = { ...filter, ...queryObj };
      }

      // Obtener las empresas con la paginación y el filtro de búsqueda
      const empresas = await db
        .collection('usuarios')
        .find(filter)
        .skip(skip)
        .limit(limit)
        .sort({ id: reverse ? -1 : 1 }) // Aplicamos orden inverso si 'reverse' es true
        .toArray();

      if (!empresas || empresas.length === 0) {
        throw new Error('No hay empresas para este usuario');
      }
      return empresas;
    },
    obtenerEmpresa: async (_, { id }, { db }) => {
      const th = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(id), rol: 'EMPRESA' });
      if (!th) {
        throw new Error('Empresa no encontrada');
      }
      return th;
    },
    listarInvitacionesUsuario: async (_, __, { db, token }) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      try {
        // Si el usuario es SUPER_ADMIN, devolver todas las invitaciones
        if (rol === 'SUPER_ADMIN') {
          const invitaciones = await db
            .collection('invitaciones')
            .find()
            .toArray();
          return invitaciones;
        }

        // Si el usuario es ADMIN, devolver solo sus invitaciones
        if (rol === 'ADMIN') {
          const invitacionesUsuario = await db
            .collection('invitaciones')
            .find({ usuarioInvitado: userId }) // Filtrar invitaciones dirigidas al usuario ADMIN
            .toArray();
          return invitacionesUsuario.map((invitacion: any) => ({
            ...invitacion,
            id: invitacion._id.toString(),
          }));
        }

        // Para otros roles, lanzar un error de permisos
        throw new Error('No tienes permisos para ver las invitaciones');
      } catch (error) {
        console.error('Error al listar invitaciones:', error);
        throw new Error('Error al obtener las invitaciones');
      }
    },

    // listaremos productos segun usuario y si el usuario pertenece a una empresa igual se listaran los productos de la empresa
    listarProductos: async (
      _,
      { page = 1, limit = 20, query = '', reverse = false },
      { db, token },
    ) => {
      const decodedToken = verifyToken(token);
      const skip = (page - 1) * limit;
      let filter = { id: decodedToken.id }; // Filtro por id de usuario

      // Si hay una consulta (query), la procesamos
      if (query) {
        const queryObj = parseQuery(query); // Parseamos la búsqueda dinámica
        filter = { ...filter, ...queryObj };
      }

      // Obtener los productos con la paginación y el filtro de búsqueda
      const productos = await db
        .collection('productos')
        .find(filter)
        .skip(skip)
        .limit(limit)
        .sort({ id: reverse ? -1 : 1 }) // Aplicamos orden inverso si 'reverse' es true
        .toArray();

      if (!productos || productos.length === 0) {
        throw new Error('No hay productos para este usuario');
      }

      return productos;
    },
  },
  Mutation: {
    login: async (_, { email, password }, { db }) => {
      // Find user in database
      const usuarioDB = await db.collection('usuarios').findOne({ email });

      if (!usuarioDB) {
        throw new Error('Usuario no encontrado');
      }

      if (usuarioDB.estado !== 'ACTIVO') {
        throw new Error('Usuario inactivo, No se confirmó el código OTP');
      }

      // Verify password
      const isValid = await bcrypt.compare(password, usuarioDB.password);
      if (!isValid) {
        throw new Error('Contraseña incorrecta');
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: usuarioDB._id, rol: usuarioDB.rol },
        env.JWT_SECRET,
        { expiresIn: '1d' },
      );

      // Transform MongoDB document to match GraphQL Usuario type
      const usuario = {
        id: usuarioDB._id.toString(), // Convert ObjectId to string
        urlImagen: usuarioDB.urlImagen || null,
        nombre: usuarioDB.nombre,
        apellido: usuarioDB.apellido,
        email: usuarioDB.email,
        password: usuarioDB.password,
        telefono: usuarioDB.telefono || null,
        rol: usuarioDB.rol,
        estado: usuarioDB.estado,
        creditos: usuarioDB.creditos,
        // Transform empresas array to match schema
        empresas: usuarioDB.empresas
          ? await Promise.all(
              usuarioDB.empresas.map(async (empresaId: any) => {
                const empresa = await db
                  .collection('empresas')
                  .findOne({ _id: empresaId });
                if (!empresa) return null;
                // retornamos todo igual a excepcion de los ObjectId que los convertimos a string
                return {
                  ...empresa,
                  _id: empresa._id.toString(),
                  usuarios: empresa.usuarios.map((u: any) => ({
                    usuario: u.usuario.toString(),
                    cargo: u.cargo,
                  })),
                };
              }),
            )
          : [],
        productos: usuarioDB.productos || [],
      };

      console.log('Token generado:', token, 'para el usuario:', usuario);

      return {
        token,
        usuario,
      };
    },
    crearAdministrador: async (_, { input }, { db, token }) => {
      // Si el rol es SUPER_ADMIN, se requiere un token para validar el rol
      if (input.rol === 'ADMIN' || input.rol === 'CLIENTE') {
        // No se requiere token para ADMIN o CLIENTE
        // Procedemos con la creación sin validar el rol en el token
      } else if (input.rol === 'SUPER_ADMIN') {
        // Validar que el token esté presente y tenga el rol adecuado
        if (!token) {
          throw new Error('No se proporcionó el token de autorización');
        }

        const decodedToken = verifyToken(token);

        // Validar el rol del token (asumimos que el token tiene información del rol)
        if (decodedToken.rol !== 'SUPER_ADMIN') {
          throw new Error(
            'El token no tiene permisos suficientes para crear usuarios',
          );
        }
      } else {
        throw new Error('Rol no permitido');
      }

      // Verificar si ya existe un usuario con el mismo email o teléfono
      const existingUser = await db.collection('usuarios').findOne({
        $or: [{ email: input.email }, { telefono: input.telefono }],
      });

      // Caso 1: Si el usuario ya existe y está "ACTIVO", lanzar un error
      if (existingUser && existingUser.estado === 'ACTIVO') {
        throw new Error(
          'Ya existe un usuario activo con este email o número de teléfono',
        );
      }

      // Caso 2: Si el usuario ya existe y está "PENDIENTE", reenviar el OTP
      if (existingUser && existingUser.estado === 'PENDIENTE') {
        // No enviar OTP si es CLIENTE
        if (input.rol !== 'CLIENTE') {
          const otp = generateOTP();
          await saveOTP(input.telefono, otp);

          try {
            await sendWhatsAppMessage(input.telefono, otp, otp.toString());
          } catch (error) {
            console.error('Error al enviar OTP por WhatsApp:', error);
            throw new Error('No se pudo enviar el código de verificación');
          }
        }

        return {
          success: true,
          message: 'Se ha reenviado un nuevo código de verificación',
          usuario: existingUser,
        };
      }

      // Caso 3: Crear un nuevo usuario
      let otp;
      if (input.rol !== 'CLIENTE') {
        // Solo generar OTP si el rol no es CLIENTE
        otp = generateOTP();
        await saveOTP(input.telefono, otp);

        try {
          await sendWhatsAppMessage(input.telefono, otp, otp.toString());
        } catch (error) {
          console.error('Error al enviar OTP por WhatsApp:', error);
          throw new Error('No se pudo enviar el código de verificación');
        }
      }

      // Determinar el estado inicial según el rol
      const estadoInicial = input.rol === 'CLIENTE' ? 'ACTIVO' : 'PENDIENTE';

      // Hash de la contraseña y creación del nuevo usuario
      const hashedPassword = await bcrypt.hash(input.password, 10);
      const usuario = {
        ...input,
        password: hashedPassword,
        estado: estadoInicial,
        rol: input.rol || 'ADMIN',
        creditos: 0,
        urlImagen: `https://www.gravatar.com/avatar/${input.email}?d=identicon`,
      };
      const result = await db.collection('usuarios').insertOne(usuario);

      // Buscar el documento recién insertado para asegurarnos de tener todos los campos
      const createdUser = await db
        .collection('usuarios')
        .findOne({ _id: result.insertedId });

      if (!createdUser) {
        throw new Error('Error al crear el usuario');
      }

      return await db
        .collection('usuarios')
        .findOne({ _id: result.insertedId });
    },
    verificarOTP: async (_, { email, telefono, otp }, { db }) => {
      const usuario = await db
        .collection('usuarios')
        .findOne({ email, telefono });
      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }
      if (usuario.estado === 'ACTIVO') {
        throw new Error('Usuario ya activo');
      }
      const isValid = await verifyOTP(telefono, otp);
      if (!isValid) {
        return {
          success: false,
          message: 'OTP inválido',
          usuario: null,
        };
      }
      await db
        .collection('usuarios')
        .updateOne(
          { email, telefono },
          { $set: { estado: 'ACTIVO', creditos: 20 } },
        );
      return {
        success: true,
        message: 'Código OTP verificado',
        usuario,
      };
    },
    actualizarAdministrador: async (_, { id, input }, { db, token }) => {
      // Verificar si el token está presente
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }
      const decodedToken = verifyToken(token);

      // Determinar el ID a actualizar (clientes o administradores solo pueden modificar su propio perfil)
      const userId = decodedToken.rol === 'SUPER_ADMIN' ? id : decodedToken.id;

      // Verificar si el usuario existe
      const existingUser = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(userId) });
      if (!existingUser) {
        throw new Error('Usuario no encontrado');
      }

      // Definir campos restringidos para cada rol
      const restrictedFieldsForClients = ['email', 'telefono'];
      const restrictedFieldsForAdmin = ['email', 'telefono'];
      const restrictedFieldsForSuperAdmin: never[] = []; // Super admin puede modificar todos los campos

      let restrictedFields;
      if (decodedToken.rol === 'SUPER_ADMIN') {
        restrictedFields = restrictedFieldsForSuperAdmin;
      } else if (decodedToken.rol === 'ADMIN') {
        restrictedFields = restrictedFieldsForAdmin;
      } else if (decodedToken.rol === 'CLIENTE') {
        restrictedFields = restrictedFieldsForClients;
      } else {
        throw new Error('Rol de usuario no reconocido');
      }

      // Filtrar el input para excluir los campos restringidos
      const filteredInput = Object.keys(input)
        .filter((key) => !restrictedFields.includes(key))
        .reduce((obj: { [key: string]: any }, key) => {
          obj[key] = input[key];
          return obj;
        }, {});

      // Si no queda nada en input después del filtrado, lanzar un error
      if (Object.keys(filteredInput).length === 0) {
        throw new Error('No tienes permiso para actualizar estos campos');
      }

      // Actualizar el usuario solo con los campos permitidos
      const result = await db
        .collection('usuarios')
        .updateOne({ _id: new ObjectId(userId) }, { $set: filteredInput });

      if (!result.matchedCount) {
        throw new Error('No se pudo actualizar el usuario');
      }

      // Retornar el usuario actualizado
      return await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(userId) });
    },
    eliminarAdministrador: async (_, { id }, { db, token }) => {
      // Verificar si el token está presente
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);

      // Determinar el ID a eliminar (admin y clientes solo pueden eliminarse a sí mismos)
      const userId = decodedToken.rol === 'SUPER_ADMIN' ? id : decodedToken.id;

      // Verificar si el usuario existe
      const existingUser = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(userId) });
      if (!existingUser) {
        throw new Error('Usuario no encontrado');
      }

      // Restricción de eliminación: solo los super admins pueden eliminar a otros usuarios
      if (decodedToken.rol !== 'SUPER_ADMIN' && userId !== decodedToken.id) {
        throw new Error('No tienes permiso para eliminar otros usuarios');
      }

      // Eliminar el usuario
      const result = await db
        .collection('usuarios')
        .deleteOne({ _id: new ObjectId(userId) });

      if (!result.deletedCount) {
        throw new Error('No se pudo eliminar el usuario');
      }

      return true;
    },
    crearEmpresa: async (_, { input }, { db, token }) => {
      // 1. Verificar el token
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      // Verificar si ya se creó una empresa por teléfono y correo
      const empresa = await db
        .collection('empresas')
        .findOne({ correo: input.correo, telefono: input.telefono });
      if (empresa) {
        throw new Error('Ya existe una empresa con este correo o teléfono');
      }

      const decodedToken = verifyToken(token);

      // 2. Verificar si el usuario tiene el rol adecuado
      if (!['ADMIN', 'SUPER_ADMIN'].includes(decodedToken.rol)) {
        throw new Error('No tienes permisos para crear una empresa');
      }

      // 3. Buscar al usuario en la base de datos
      const usuario = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(decodedToken.id) });

      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }

      // 4. Verificar que el usuario tenga suficientes créditos
      if (usuario.creditos < 5) {
        throw new Error(
          'No tienes suficientes créditos para crear una empresa',
        );
      }

      // 5. Crear la empresa en la base de datos
      const nuevaEmpresa = {
        ...input,
        usuarios: [{ usuario: decodedToken.id, cargo: 'ADMIN_EMPRESA' }],
        urlImagen: `https://www.gravatar.com/avatar/${input.correo}?d=identicon`,
        productos: [],
        createdAt: new Date(),
        updatedAt: new Date(),
        usucreAt: decodedToken.id,
        usuactAt: decodedToken.id,
      };

      const { insertedId } = await db
        .collection('empresas')
        .insertOne(nuevaEmpresa);

      // 6. Descontar créditos del usuario y actualizarlo en la base de datos
      await db.collection('usuarios').updateOne(
        { _id: new ObjectId(decodedToken.id) },
        {
          $inc: { creditos: -5 },
          $push: { empresas: insertedId }, // Agregar el ID de la nueva empresa al campo `empresas` del usuario
        },
      );

      // 7. Retornar la información de la nueva empresa creada
      return await db
        .collection('empresas')
        .findOne({ _id: new ObjectId(insertedId) });
    },
    actualizarEmpresa: async (
      _,
      { id, input, usuariosEliminados = [] },
      { db, token },
    ) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }
      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      // Verificar permisos del SUPER_ADMIN o ADMIN con rol en la empresa
      if (rol === 'SUPER_ADMIN') {
        // SUPER_ADMIN tiene acceso completo sin restricciones
      } else if (rol === 'ADMIN') {
        const empresa = await db.collection('empresas').findOne({
          _id: new ObjectId(id),
          usuarios: {
            $elemMatch: {
              usuario: userId,
              cargo: 'ADMIN_EMPRESA',
            },
          },
        });

        if (!empresa) {
          throw new Error(
            'No tienes permisos suficientes para actualizar esta empresa',
          );
        }
      } else {
        throw new Error('No tienes permisos para realizar esta acción');
      }

      // Actualizar la información de la empresa si hay input
      if (Object.keys(input).length > 0) {
        const result = await db
          .collection('empresas')
          .updateOne({ _id: new ObjectId(id) }, { $set: input });

        if (!result.matchedCount) {
          throw new Error('No se pudo actualizar la empresa');
        }
      }

      // Procesar eliminación de usuarios
      // Modificar la sección de eliminación de usuarios en actualizarEmpresa
      if (usuariosEliminados.length > 0) {
        const empresa = await db
          .collection('empresas')
          .findOne({ _id: new ObjectId(id) });

        if (!empresa) {
          throw new Error('Empresa no encontrada');
        }

        // Actualizar la empresa eliminando los usuarios
        const updateResult = await db.collection('empresas').updateOne(
          { _id: new ObjectId(id) },
          {
            $pull: {
              usuarios: {
                usuario: { $in: usuariosEliminados },
              },
            },
          },
        );

        // También actualizar los usuarios eliminados para quitar la referencia a la empresa
        await db.collection('usuarios').updateMany(
          {
            _id: {
              $in: usuariosEliminados.map((id: number) => new ObjectId(id)),
            },
          },
          {
            $pull: {
              empresas: new ObjectId(id),
            },
          },
        );

        if (!updateResult.modifiedCount) {
          throw new Error('No se pudieron eliminar los usuarios');
        }
      }

      // Obtener y retornar la empresa actualizada
      const empresaActualizada = await db
        .collection('empresas')
        .findOne({ _id: new ObjectId(id) });

      if (!empresaActualizada) {
        throw new Error('No se pudo obtener la empresa actualizada');
      }
      return empresaActualizada;
    },
    eliminarEmpresa: async (_, { id }, { db, token }) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      console.log('Intento de eliminación de empresa:', {
        empresaId: id,
        usuarioId: userId,
        rolUsuario: rol,
      });

      // Verificar si la empresa existe
      const empresa = await db
        .collection('empresas')
        .findOne({ _id: new ObjectId(id) });

      if (!empresa) {
        throw new Error('Empresa no encontrada');
      }

      // Verificar permisos
      if (rol === 'SUPER_ADMIN') {
        // El SUPER_ADMIN tiene permiso total, puede continuar
        console.log('Eliminación autorizada: Usuario es SUPER_ADMIN');
      } else {
        // Para otros roles, verificar si es ADMIN_EMPRESA
        const esAdminEmpresa = empresa.usuarios.some(
          (usuario: { usuario: string; cargo: string }) =>
            usuario.usuario === userId && usuario.cargo === 'ADMIN_EMPRESA',
        );

        if (!esAdminEmpresa) {
          console.log('Eliminación denegada: Usuario no es ADMIN_EMPRESA');
          throw new Error('No tienes permisos para eliminar esta empresa');
        }
        console.log('Eliminación autorizada: Usuario es ADMIN_EMPRESA');
      }

      try {
        // Primero, obtenemos todos los usuarios asociados a la empresa
        const usuariosEmpresa = empresa.usuarios.map(
          (u: { usuario: any }) => u.usuario,
        );
        console.log('Usuarios asociados a la empresa:', usuariosEmpresa);

        // Eliminar la empresa
        const resultadoEliminacion = await db.collection('empresas').deleteOne({
          _id: new ObjectId(id),
        });

        if (resultadoEliminacion.deletedCount === 0) {
          throw new Error('No se pudo eliminar la empresa');
        }

        // También podrías querer actualizar la referencia en los usuarios
        // Esto es opcional, dependiendo de tu lógica de negocio
        if (usuariosEmpresa.length > 0) {
          await db.collection('usuarios').updateMany(
            {
              _id: {
                $in: usuariosEmpresa.map((id: number) => new ObjectId(id)),
              },
            },
            { $pull: { empresas: new ObjectId(id) } },
          );
        }

        // Retornar la empresa eliminada
        return true;
      } catch (error) {
        throw new Error(
          'Error al eliminar la empresa: ' + (error as Error).message,
        );
      }
    },
    invitarUsuarioAEmpresa: async (_, { email, empresaId }, { db, token }) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      console.log('Intento de invitación:', {
        empresaId,
        email,
        usuarioInvitante: userId,
        rolInvitante: rol,
      });

      try {
        // 1. Verificar si el usuario a invitar existe
        const usuarioInvitado = await db
          .collection('usuarios')
          .findOne({ email });

        if (!usuarioInvitado) {
          return {
            success: false,
            message:
              'El correo electrónico no corresponde a ningún usuario registrado',
            invitacion: null,
          };
        }

        // 2. Verificar si la empresa existe
        const empresa = await db
          .collection('empresas')
          .findOne({ _id: new ObjectId(empresaId) });

        if (!empresa) {
          return {
            success: false,
            message: 'La empresa no existe',
            invitacion: null,
          };
        }

        // 3. Verificar permisos
        if (rol !== 'SUPER_ADMIN') {
          const esAdminEmpresa = empresa.usuarios.some(
            (u: { usuario: string; cargo: string }) =>
              u.usuario === userId && u.cargo === 'ADMIN_EMPRESA',
          );

          if (!esAdminEmpresa) {
            return {
              success: false,
              message:
                'No tienes permisos para enviar invitaciones en esta empresa',
              invitacion: null,
            };
          }
        }

        // 4. Verificar si ya existe una invitación pendiente
        const invitacionExistente = await db
          .collection('invitaciones')
          .findOne({
            email,
            'empresa._id': new ObjectId(empresaId),
            estado: 'PENDIENTE',
          });

        if (invitacionExistente) {
          return {
            success: false,
            message: 'Ya existe una invitación pendiente para este usuario',
            invitacion: {
              id: invitacionExistente._id.toString(),
              email: invitacionExistente.email,
              empresa: invitacionExistente.empresa,
              estado: invitacionExistente.estado,
            },
          };
        }

        // 5. Verificar si el usuario ya está en la empresa
        const yaEsMiembro = empresa.usuarios.some(
          (u: { usuario: any }) => u.usuario === usuarioInvitado._id.toString(),
        );
        if (yaEsMiembro) {
          return {
            success: false,
            message: 'El usuario ya es miembro de esta empresa',
            invitacion: null,
          };
        }

        // 6. Crear la invitación y almacenar el usuario invitado
        const nuevaInvitacion = {
          _id: new ObjectId(),
          email,
          empresa: {
            _id: empresa._id,
            nombre: empresa.nombre,
          },
          estado: 'PENDIENTE',
          fechaCreacion: new Date(),
          usuarioInvitante: userId,
          usuarioInvitado: usuarioInvitado._id.toString(), // Aquí se almacena el ID del usuario invitado
        };

        await db.collection('invitaciones').insertOne(nuevaInvitacion);

        // 7. Crear y enviar la notificación
        const notificacion = {
          id: new ObjectId().toString(),
          mensaje: `Has recibido una invitación para unirte a la empresa ${empresa.nombre}`,
          fecha: new Date().toISOString(),
          usuarioId: usuarioInvitado._id.toString(), // ID del usuario que recibirá la notificación
        };

        // Publicar la notificación
        pubsub.publish(NOTIFICACION_CHANNEL, {
          notificacionRecibida: notificacion,
        });

        return {
          success: true,
          message: 'Invitación enviada exitosamente',
          invitacion: {
            id: nuevaInvitacion._id.toString(),
            email: nuevaInvitacion.email,
            empresa,
            estado: nuevaInvitacion.estado,
          },
        };
      } catch (error) {
        console.error('Error al crear invitación:', error);
        return {
          success: false,
          message:
            'Error al procesar la invitación: ' + (error as Error).message,
          invitacion: null,
        };
      }
    },
    aceptarInvitacionEmpresa: async (_, { id }, { db, token }) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      // 1. Verificar si la invitación existe y está pendiente
      const invitacion = await db
        .collection('invitaciones')
        .findOne({ _id: new ObjectId(id), estado: 'PENDIENTE' });

      if (!invitacion) {
        throw new Error('Invitación no encontrada o ya fue aceptada/rechazada');
      }

      // 2. Verificar si el usuario existe
      const usuario = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(userId) });

      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }

      // 3. Verificar si el usuario ya es miembro de la empresa
      const empresa = await db
        .collection('empresas')
        .findOne({ _id: invitacion.empresa._id });

      if (!empresa) {
        throw new Error('Empresa no encontrada');
      }

      const yaEsMiembro = empresa.usuarios.some(
        (u: { usuario: string }) => u.usuario === userId,
      );
      if (yaEsMiembro) {
        throw new Error('El usuario ya es miembro de esta empresa');
      }

      // 4. Actualizar la empresa con el nuevo usuario
      await db.collection('empresas').updateOne(
        { _id: invitacion.empresa._id },
        {
          $push: {
            usuarios: {
              usuario: userId,
              cargo: 'EMPLEADO',
            },
          },
        },
      );

      // 5. Actualizar el usuario con la nueva empresa
      await db.collection('usuarios').updateOne(
        { _id: new ObjectId(userId) },
        {
          $push: { empresas: invitacion.empresa._id },
        },
      );

      // 6. Actualizar la invitación a "ACEPTADA"
      await db.collection('invitaciones').updateOne(
        { _id: new ObjectId(id) },
        {
          $set: { estado: 'ACEPTADA' },
        },
      );

      return true;
    },
    rechazarInvitacionEmpresa: async (_, { id }, { db, token }) => {
      if (!token) {
        throw new Error('No se proporcionó el token de autorización');
      }

      const decodedToken = verifyToken(token);
      const { rol, id: userId } = decodedToken;

      // 1. Verificar si la invitación existe y está pendiente
      const invitacion = await db
        .collection('invitaciones')
        .findOne({ _id: new ObjectId(id), estado: 'PENDIENTE' });

      if (!invitacion) {
        throw new Error('Invitación no encontrada o ya fue aceptada/rechazada');
      }

      // 2. Verificar si el usuario existe
      const usuario = await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(userId) });

      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }

      // 3. Actualizar la invitación a "RECHAZADA"
      await db.collection('invitaciones').updateOne(
        { _id: new ObjectId(id) },
        {
          $set: { estado: 'RECHAZADA' },
        },
      );

      return true;
    },

    crearProducto: async (_, { input }, { db, token }) => {
      if (!token) throw new Error('No se proporcionó el token de autorización');

      const decodedToken = verifyToken(token);
      if (!['ADMIN', 'SUPER_ADMIN'].includes(decodedToken.rol)) {
        throw new Error('No tienes permisos para crear productos');
      }

      const productoId = new ObjectId();
      let imagenUrl = null;

      try {
        // Validación de la empresa y pertenencia del usuario
        let empresa = null;
        if (input.empresaId) {
          empresa = await db
            .collection('empresas')
            .findOne({ _id: new ObjectId(input.empresaId) });

          if (!empresa) {
            throw new Error('La empresa especificada no existe');
          }

          // Verificar si el usuario pertenece a la empresa
          const usuarioEnEmpresa = empresa.usuarios.some(
            (u: any) => u.usuario === decodedToken.id,
          );

          if (!usuarioEnEmpresa) {
            throw new Error(
              'No tienes permisos para crear productos en esta empresa',
            );
          }
        }

        // Procesar imagen si existe
        if (input.imagen) {
          const { createReadStream, filename } = await input.imagen;
          const extension = path.extname(filename);
          const nombreArchivo = `${productoId}-${Date.now()}${extension}`;
          const rutaImagen = path.join(
            __dirname,
            '../uploads/productos',
            nombreArchivo,
          );

          await new Promise((resolve, reject) => {
            createReadStream()
              .pipe(fs.createWriteStream(rutaImagen))
              .on('finish', resolve)
              .on('error', reject);
          });

          imagenUrl = `/uploads/productos/${nombreArchivo}`;
        }

        // Crear el nuevo producto con campos iniciales
        const nuevoProducto = {
          _id: productoId,
          id: productoId.toString(),
          nombre: input.nombre,
          imagen: imagenUrl,
          plataforma: input.plataforma,
          versiones: [] as any[],
          usuarios: [] as ObjectId[],
          empresa: input.empresaId ? new ObjectId(input.empresaId) : null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          usucreAt: decodedToken.id,
          usuactAt: decodedToken.id,
        };

        // Preparación de usuarios
        if (input.empresaId) {
          // Si hay empresa, solo incluir usuarios adicionales que no estén en la empresa
          const usuariosEmpresa = new Set(
            empresa.usuarios.map((u: any) => u.usuario),
          );
          const usuariosAdicionales = input.usuarioId.filter(
            (id: string) => !usuariosEmpresa.has(id),
          );
          nuevoProducto.usuarios = usuariosAdicionales.map(
            (id: string) => new ObjectId(id),
          );
        } else {
          // Si no hay empresa, incluir el usuario creador y los adicionales
          const usuariosUnicos = new Set([decodedToken.id, ...input.usuarioId]);
          nuevoProducto.usuarios = Array.from(usuariosUnicos).map(
            (id: string) => new ObjectId(id),
          );
        }

        // Crear versión del producto y calcular hash para validar unicidad
        const versionId = new ObjectId();
        const { createReadStream: versionStream, filename: versionFilename } =
          await input.version.archivo;
        const hash = await calcularHashArchivo(versionStream());

        // Verificar que el hash no exista en otras versiones
        const versionExistente = await db
          .collection('versiones')
          .findOne({ hash });
        // if (versionExistente) {
        //   throw new Error('Este archivo ya existe como una versión previa.');
        // }

        // Verificar que el número de versión no esté duplicado para el mismo producto
        const versionDuplicada = await db.collection('versiones').findOne({
          producto: productoId,
          numeroVersion: input.version.numeroVersion,
        });
        // if (versionDuplicada) {
        //   throw new Error(
        //     'Este número de versión ya existe para este producto.',
        //   );
        // }

        // Guardar archivo de la versión
        const versionPath = path.join(
          __dirname,
          `../uploads/productos/${productoId}`,
        );
        await fs.promises.mkdir(versionPath, { recursive: true });
        const rutaArchivo = path.join(versionPath, versionFilename);

        await new Promise((resolve, reject) => {
          versionStream()
            .pipe(fs.createWriteStream(rutaArchivo))
            .on('finish', resolve)
            .on('error', reject);
        });

        const nuevaVersion = {
          _id: versionId,
          id: versionId.toString(),
          numeroVersion: input.version.numeroVersion,
          archivo: rutaArchivo,
          hash,
          tamanioArchivo: (await fs.promises.stat(rutaArchivo)).size,
          tipoArchivo: path.extname(versionFilename),
          cambios: input.version.cambios,
          estado: 'ACTIVA',
          producto: productoId,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          usucreAt: decodedToken.id,
          usuactAt: decodedToken.id,
        };

        const licencias = input.licencias.map((licencia: any) => ({
          _id: new ObjectId(),
          id: new ObjectId().toString(),
          ...licencia,
          codigoActivacion: generateLicenseCode(),
          estado: 'ACTIVA',
          conexionesActivas: [],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }));

        const session = db.client.startSession();
        try {
          await session.withTransaction(async () => {
            await db.collection('productos').insertOne(nuevoProducto);
            await db.collection('versiones').insertOne(nuevaVersion);
            if (licencias.length > 0) {
              await db.collection('licencias').insertMany(licencias);
            }

            // Si se especifica una empresa, agregar el producto en la empresa
            if (input.empresaId) {
              await db
                .collection('empresas')
                .updateOne(
                  { _id: new ObjectId(input.empresaId) },
                  { $push: { productos: productoId } },
                );
            }

            // Registrar el producto en cada usuario asociado individualmente
            for (const usuarioId of nuevoProducto.usuarios) {
              await db
                .collection('usuarios')
                .updateOne(
                  { _id: usuarioId },
                  { $push: { productos: productoId } },
                );
            }
          });

          // Obtener los usuarios completos para el campo usuario
          const usuarios = await db
            .collection('usuarios')
            .find({ _id: { $in: nuevoProducto.usuarios } })
            .toArray();

          // Construir la respuesta según el schema
          const productResponse = {
            id: nuevoProducto.id,
            nombre: nuevoProducto.nombre,
            imagen: nuevoProducto.imagen,
            plataforma: nuevoProducto.plataforma,
            // Si hay empresa, incluir la estructura UsuarioEnProducto
            empresa: input.empresaId
              ? [
                  {
                    usuario: empresa.usuarios[0].usuario, // Primer usuario de la empresa
                    cargo: 'ADMIN_PRODUCTO',
                  },
                ]
              : null,
            usuario: nuevoProducto.usuarios.map((id) => id.toString()),
            versiones: [nuevaVersion],
            versionActual: nuevaVersion,
            licencias: licencias.map(
              (licencia: {
                id: any;
                email: any;
                maxConexiones: any;
                conexionesActivas: any;
                estado: any;
                codigoActivacion: any;
                fechaVencimiento: any;
                reglas: any;
                createdAt: any;
                updatedAt: any;
              }) => ({
                id: licencia.id,
                email: licencia.email,
                maxConexiones: licencia.maxConexiones,
                conexionesActivas: licencia.conexionesActivas,
                estado: licencia.estado,
                codigoActivacion: licencia.codigoActivacion,
                fechaActivacion: null,
                fechaVencimiento: licencia.fechaVencimiento,
                reglas: licencia.reglas,
                createdAt: licencia.createdAt,
                updatedAt: licencia.updatedAt,
              }),
            ),
            createdAt: nuevoProducto.createdAt,
            updatedAt: nuevoProducto.updatedAt,
            usucreAt: nuevoProducto.usucreAt,
            usuactAt: nuevoProducto.usuactAt,
          };

          return productResponse;
        } finally {
          await session.endSession();
        }
      } catch (error) {
        throw new Error(`Error al crear producto: ${(error as Error).message}`);
      }
    },
    actualizarProducto: async (
      _,
      { id, input, usuariosEliminados, empresaEliminada },
      { db, token },
    ) => {
      if (!token) throw new Error('No se proporcionó el token de autorización');

      const decodedToken = verifyToken(token);
      const productoId = new ObjectId(id);

      // Obtener el producto actual
      const productoActual = await db
        .collection('productos')
        .findOne({ _id: productoId });
      if (!productoActual) {
        throw new Error('Producto no encontrado');
      }

      // Verificar si el usuario tiene permisos para actualizar el producto
      const tienePermiso =
        ['ADMIN', 'SUPER_ADMIN'].includes(decodedToken.rol) ||
        productoActual.usucreAt === decodedToken.id;
      if (!tienePermiso) {
        throw new Error('No tienes permisos para actualizar este producto');
      }

      try {
        const session = db.client.startSession();
        await session.withTransaction(async () => {
          // 1. Primero manejamos los campos básicos
          const actualizacionBasica: any = {
            $set: {
              updatedAt: new Date().toISOString(),
              usuactAt: decodedToken.id,
            },
          };

          if (input.nombre) actualizacionBasica.$set.nombre = input.nombre;
          if (input.plataforma)
            actualizacionBasica.$set.plataforma = input.plataforma;

          // 2. Procesar imagen si existe
          if (input.imagen) {
            const { createReadStream, filename } = await input.imagen;
            const extension = path.extname(filename);
            const nombreArchivo = `${productoId}-${Date.now()}${extension}`;
            const rutaImagen = path.join(
              __dirname,
              '../uploads/productos',
              nombreArchivo,
            );

            await new Promise((resolve, reject) => {
              createReadStream()
                .pipe(fs.createWriteStream(rutaImagen))
                .on('finish', resolve)
                .on('error', reject);
            });

            actualizacionBasica.$set.imagen = `/uploads/productos/${nombreArchivo}`;

            if (productoActual.imagen) {
              const rutaAnterior = path.join(
                __dirname,
                '..',
                productoActual.imagen,
              );
              await fs.promises.unlink(rutaAnterior).catch(() => {});
            }
          }

          // 3. Manejar empresa si es necesario
          if (empresaEliminada && productoActual.empresa) {
            const empresa = await db
              .collection('empresas')
              .findOne({ _id: productoActual.empresa });
            const esAdminEmpresa = empresa.usuarios.some(
              (u: any) => u.usuario === decodedToken.id && u.rol === 'ADMIN',
            );

            if (
              !esAdminEmpresa &&
              productoActual.usucreAt !== decodedToken.id
            ) {
              throw new Error('No tienes permisos para desvincular la empresa');
            }

            await db
              .collection('empresas')
              .updateOne(
                { _id: productoActual.empresa },
                { $pull: { productos: productoId } },
              );

            actualizacionBasica.$set.empresa = null;
          } else if (input.empresaId) {
            const nuevaEmpresa = await db.collection('empresas').findOne({
              _id: new ObjectId(input.empresaId),
            });

            if (!nuevaEmpresa) {
              throw new Error('La empresa especificada no existe');
            }

            actualizacionBasica.$set.empresa = new ObjectId(input.empresaId);
          }

          // Aplicar actualizaciones básicas primero
          await db
            .collection('productos')
            .updateOne({ _id: productoId }, actualizacionBasica);

          // 4. Manejar eliminación de usuarios
          if (usuariosEliminados && usuariosEliminados.length > 0) {
            if (productoActual.usucreAt !== decodedToken.id) {
              throw new Error(
                'Solo el creador del producto puede eliminar usuarios',
              );
            }

            const usuariosAEliminar = usuariosEliminados.map(
              (id: number) => new ObjectId(id),
            );

            // Verificar auto-eliminación del creador
            const creadorSeAutoElimina = usuariosAEliminar.some(
              (id: { toString: () => any }) =>
                id.toString() === productoActual.usucreAt,
            );

            if (creadorSeAutoElimina) {
              // Obtener lista actual de usuarios después de las posibles actualizaciones
              const productoActualizado = await db
                .collection('productos')
                .findOne({ _id: productoId });
              const usuariosRestantes = productoActualizado.usuarios.filter(
                (userId: any) =>
                  !usuariosAEliminar.some(
                    (elimId: { equals: (arg0: any) => any }) =>
                      elimId.equals(userId),
                  ),
              );

              if (usuariosRestantes.length === 0) {
                throw new Error(
                  'No puedes eliminarte como creador si no hay otros usuarios',
                );
              }

              if (!input.nuevoCreadorId) {
                throw new Error(
                  'Debes especificar un nuevo creador antes de eliminarte',
                );
              }

              const nuevoCreadorObjectId = new ObjectId(input.nuevoCreadorId);
              if (
                !usuariosRestantes.some(
                  (id: { equals: (arg0: ObjectId) => any }) =>
                    id.equals(nuevoCreadorObjectId),
                )
              ) {
                throw new Error(
                  'El nuevo creador debe ser un usuario actual del producto',
                );
              }

              // Actualizar el creador primero
              await db
                .collection('productos')
                .updateOne(
                  { _id: productoId },
                  { $set: { usucreAt: input.nuevoCreadorId } },
                );
            }

            // Eliminar usuarios en una operación separada
            await db
              .collection('productos')
              .updateOne(
                { _id: productoId },
                { $pull: { usuarios: { $in: usuariosAEliminar } } },
              );

            // Actualizar referencias en usuarios
            await db
              .collection('usuarios')
              .updateMany(
                { _id: { $in: usuariosAEliminar } },
                { $pull: { productos: productoId } },
              );
          }

          // 5. Agregar nuevos usuarios en una operación separada
          if (input.usuarioId && input.usuarioId.length > 0) {
            const nuevosUsuarios = input.usuarioId.map(
              (id: number) => new ObjectId(id),
            );

            // Obtener lista actualizada de usuarios del producto
            const productoActualizado = await db
              .collection('productos')
              .findOne({ _id: productoId });
            const usuariosActuales = new Set(
              productoActualizado.usuarios.map((id: { toString: () => any }) =>
                id.toString(),
              ),
            );
            const usuariosNuevos = nuevosUsuarios.filter(
              (id: { toString: () => unknown }) =>
                !usuariosActuales.has(id.toString()),
            );

            if (usuariosNuevos.length > 0) {
              // Verificar que los usuarios existan
              const usuariosExistentes = await db
                .collection('usuarios')
                .countDocuments({
                  _id: { $in: usuariosNuevos },
                });

              if (usuariosExistentes !== usuariosNuevos.length) {
                throw new Error('Uno o más usuarios especificados no existen');
              }

              // Agregar nuevos usuarios al producto
              await db
                .collection('productos')
                .updateOne(
                  { _id: productoId },
                  { $addToSet: { usuarios: { $each: usuariosNuevos } } },
                );

              // Actualizar referencias en usuarios
              await db
                .collection('usuarios')
                .updateMany(
                  { _id: { $in: usuariosNuevos } },
                  { $addToSet: { productos: productoId } },
                );
            }
          }
        });

        // Obtener y retornar el producto actualizado
        const productoActualizado = await db
          .collection('productos')
          .findOne({ _id: productoId });


        const response = {
          id: productoActualizado._id.toString(),
          nombre: productoActualizado.nombre,
          imagen: productoActualizado.imagen,
          plataforma: productoActualizado.plataforma,
          empresa: productoActualizado.empresa
            ? {
                id: productoActualizado.empresa.toString(),
              }
            : null,
          usuario: productoActualizado.usuarios.map(
            (id: { toString: () => any }) => id.toString(),
          ),
          historialCambios: productoActualizado.historialCambios,
          versiones: productoActualizado.versiones,
          createdAt: productoActualizado.createdAt,
          updatedAt: productoActualizado.updatedAt,
          usucreAt: productoActualizado.usucreAt,
          usuactAt: productoActualizado.usuactAt,
        };
        console.log('Producto actualizado:', response);

        return response;
      } catch (error) {
        throw new Error(
          `Error al actualizar producto: ${(error as Error).message}`,
        );
      }
    },
  },
  Subscription: {
    notificacionRecibida: {
      subscribe: withFilter(
        () => pubsub.asyncIterator([NOTIFICACION_CHANNEL]),
        (payload, variables, { token }) => {
          if (!token) return false;

          try {
            const decodedToken = verifyToken(token);
            // Solo enviar la notificación al usuario destinatario
            return payload.notificacionRecibida.usuarioId === decodedToken.id;
          } catch (error) {
            return false;
          }
        },
      ),
    },
  },
};

export default userResolvers;

function generateLicenseCode() {
  return (
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15)
  );
}

async function calcularHashArchivo(stream: {
  on: (
    arg0: string,
    arg1: (data: any) => crypto.Hash,
  ) => {
    (): any;
    new (): any;
    on: {
      (
        arg0: string,
        arg1: () => void,
      ): {
        (): any;
        new (): any;
        on: { (arg0: string, arg1: (reason?: any) => void): void; new (): any };
      };
      new (): any;
    };
  };
}) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    stream
      .on('data', (data: crypto.BinaryLike) => hash.update(data))
      .on('end', () => resolve(hash.digest('hex')))
      .on('error', reject);
  });
}
