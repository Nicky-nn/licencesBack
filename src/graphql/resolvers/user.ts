/* eslint-disable @typescript-eslint/no-unused-vars */
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
  Query: {
    me: async (_, __, { db, token }) => {
      const decodedToken = verifyToken(token);
      return await db
        .collection('usuarios')
        .findOne({ _id: new ObjectId(decodedToken.id) });
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
      const usuario = await db.collection('usuarios').findOne({ email });
      if (!usuario) {
        throw new Error('Usuario no encontrado');
      }
      if (usuario.estado !== 'ACTIVO') {
        throw new Error('Usuario inactivo, No se confirmó el código OTP');
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
    // SOLO UN SUPERADMIN PUEDE CREAR OTRO SUPERADMIN y ADMIN, por defcto el rol es ADMIN

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
  },
};

export default userResolvers;
