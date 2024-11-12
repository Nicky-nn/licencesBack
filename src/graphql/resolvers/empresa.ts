// import { IResolvers } from '@graphql-tools/utils';
// import { ObjectId } from 'mongodb';
// import { withFilter } from 'graphql-subscriptions';
// import { JwtPayload } from 'jsonwebtoken';
// import { env } from '../../config/env';
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';

// const verifyToken = (token: string): JwtPayload => {
//   if (!token) {
//     throw new Error('Token no proporcionado');
//   }

//   try {
//     return jwt.verify(token.split(' ')[1], env.JWT_SECRET) as JwtPayload;
//   } catch (error) {
//     throw new Error('Token inválido');
//   }
// };

// const getGravatarUrl = (email: string) => {
//   const hash = crypto
//     .createHash('md5')
//     .update(email.trim().toLowerCase())
//     .digest('hex');
//   return `https://www.gravatar.com/avatar/${hash}?d=identicon`;
// };

// const empresaResolvers: IResolvers = {
//   Query: {
//     obtenerEmpresa: async (_, { id }, { db, token }) => {
//       const decodedToken = verifyToken(token);
//       if (!decodedToken) {
//         throw new Error('Token inválido');
//       }

//       if (!ObjectId.isValid(id)) {
//         throw new Error('Identificador de empresa inválido');
//       }
//       return await db.collection('empresas').findOne({ _id: new ObjectId(id) });
//     },
//     listarEmpresas: async (_, __, { db, token }) => {
//       const decodedToken = verifyToken(token);
//       if (!decodedToken) {
//         throw new Error('Token inválido');
//       }

//       const empresas = await db
//         .collection('empresas')
//         .find({
//           usuarios: new ObjectId(decodedToken.id),
//         })
//         .toArray();

//       if (empresas.length === 0) {
//         throw new Error('No perteneces a ninguna empresa');
//       }

//       const empresasConUsuarios = await Promise.all(
//         empresas.map(async (empresa: { _id: { toString: () => any } }) => {
//           return {
//             ...empresa,
//             id: empresa._id.toString(),
//           };
//         }),
//       );
//       console.log(
//         'empresasConUsuariosJSON:',
//         JSON.stringify(empresasConUsuarios, null, 2),
//       );

//       return empresasConUsuarios;
//     },
//   },
//   Mutation: {
//     crearEmpresa: async (_, { nombre }, { db, token }) => {
//       const decodedToken = verifyToken(token);
//       if (
//         !decodedToken ||
//         (decodedToken.rol !== 'ADMIN' && decodedToken.rol !== 'SUPER_ADMIN')
//       ) {
//         throw new Error('No tienes permisos para crear empresas');
//       }

//       const urlImge = getGravatarUrl(
//         decodedToken.email || 'default@gravatar.com',
//       );

//       const result = await db.collection('empresas').insertOne({
//         nombre,
//         usuarios: [new ObjectId(decodedToken.id)],
//         usuCre: decodedToken.id,
//         fechaCre: new Date(),
//         usuMod: decodedToken.id,
//         fechaMod: new Date(),
//         urlImge, // Agrega la URL de la imagen aquí
//       });
//       return {
//         id: result.insertedId,
//         nombre,
//         usuarios: [decodedToken.id],
//         urlImge,
//       };
//     },
//     actualizarEmpresa: async (_, { id, nombre, urlImge }, { db, token }) => {
//       const decodedToken = verifyToken(token);
//       if (
//         !decodedToken ||
//         (decodedToken.rol !== 'ADMIN' && decodedToken.rol !== 'SUPER_ADMIN')
//       ) {
//         throw new Error('No tienes permisos para actualizar empresas');
//       }

//       if (!ObjectId.isValid(id)) {
//         throw new Error('Identificador de empresa inválido');
//       }
//       const updateData: any = {
//         usuMod: decodedToken.id,
//         fechaMod: new Date(),
//       };
//       if (nombre !== undefined) updateData.nombre = nombre;
//       if (urlImge !== undefined) updateData.urlImge = urlImge;

//       await db
//         .collection('empresas')
//         .updateOne({ _id: new ObjectId(id) }, { $set: updateData });
//       const updatedEmpresa = await db
//         .collection('empresas')
//         .findOne({ _id: new ObjectId(id) });
//       return updatedEmpresa
//         ? { ...updatedEmpresa, id: updatedEmpresa._id.toString() }
//         : null;
//     },
//     eliminarEmpresa: async (_, { id }, { db, token }) => {
//       const decodedToken = verifyToken(token);
//       if (!decodedToken || decodedToken.rol !== 'SUPER_ADMIN') {
//         throw new Error('No tienes permisos para eliminar empresas');
//       }

//       if (!ObjectId.isValid(id)) {
//         throw new Error('Identificador de empresa inválido');
//       }
//       const result = await db
//         .collection('empresas')
//         .deleteOne({ _id: new ObjectId(id) });
//       return result.deletedCount === 1;
//     },
//     invitarUsuarioAEmpresa: async (
//       _,
//       { email, empresaId },
//       { db, token, pubsub },
//     ) => {
//       const decodedToken = verifyToken(token);
//       if (
//         !decodedToken ||
//         (decodedToken.rol !== 'ADMIN' && decodedToken.rol !== 'SUPER_ADMIN')
//       ) {
//         throw new Error('No tienes permisos para invitar usuarios');
//       }

//       if (!ObjectId.isValid(empresaId)) {
//         throw new Error('Identificador de empresa inválido');
//       }

//       const empresa = await db
//         .collection('empresas')
//         .findOne({ _id: new ObjectId(empresaId) });
//       if (!empresa) {
//         throw new Error('Empresa no encontrada');
//       }

//       // Verificar si el usuario ya está en la empresa
//       const usuarioExistente = await db.collection('usuarios').findOne({
//         email: email,
//         'empresas._id': new ObjectId(empresaId),
//       });
//       if (usuarioExistente) {
//         throw new Error('El usuario ya pertenece a esta empresa');
//       }

//       const empresaWithId = {
//         ...empresa,
//         id: empresa._id.toString(),
//       };

//       // Buscar una invitación existente
//       let invitacion = await db.collection('invitaciones').findOne({
//         email: email,
//         empresaId: new ObjectId(empresaId),
//         estado: 'PENDIENTE',
//       });

//       if (!invitacion) {
//         // Crear una nueva invitación si no existe
//         invitacion = {
//           email,
//           empresaId: new ObjectId(empresaId),
//           estado: 'PENDIENTE',
//           usuCre: decodedToken.id,
//           fechaCre: new Date(),
//         };

//         const result = await db
//           .collection('invitaciones')
//           .insertOne(invitacion);
//         invitacion._id = result.insertedId;
//       } else {
//         // Actualizar la fecha de la invitación existente
//         await db
//           .collection('invitaciones')
//           .updateOne(
//             { _id: invitacion._id },
//             { $set: { fechaMod: new Date() } },
//           );
//       }

//       const nuevaInvitacion = {
//         id: invitacion._id.toString(),
//         email,
//         empresa: empresaWithId,
//         estado: 'PENDIENTE',
//         usuCre: invitacion.usuCre,
//         fechaCre: invitacion.fechaCre,
//         fechaMod: invitacion.fechaMod || invitacion.fechaCre,
//       };

//       pubsub.publish('INVITACION_EMPRESA_RECIBIDA', {
//         invitacionEmpresaRecibida: nuevaInvitacion,
//       });

//       return nuevaInvitacion;
//     },

//     aceptarInvitacionEmpresa: async (_, { invitacionId }, { db, token }) => {
//       console.log('Iniciando aceptarInvitacionEmpresa');
//       console.log('invitacionId recibido:', invitacionId);

//       if (!invitacionId) {
//         throw new Error('Identificador de invitación no proporcionado');
//       }

//       const decodedToken = verifyToken(token);
//       if (!decodedToken || !decodedToken.id) {
//         throw new Error('Token inválido o no contiene ID de usuario');
//       }

//       console.log('Token decodificado:', decodedToken);

//       // Buscar el usuario en la base de datos
//       const usuario = await db
//         .collection('usuarios')
//         .findOne({ _id: new ObjectId(decodedToken.id) });
//       if (!usuario || !usuario.email) {
//         throw new Error('Usuario no encontrado o sin email');
//       }

//       console.log('Email del usuario:', usuario.email);

//       let objectId;
//       try {
//         objectId = new ObjectId(invitacionId);
//       } catch (error) {
//         console.error('Error al convertir invitacionId a ObjectId:', error);
//         throw new Error('Identificador de invitación inválido');
//       }

//       console.log('ObjectId creado:', objectId);

//       const invitacion = await db.collection('invitaciones').findOne({
//         _id: objectId,
//         email: usuario.email,
//         estado: 'PENDIENTE',
//       });

//       console.log('Invitación encontrada:', invitacion);

//       if (!invitacion) {
//         throw new Error('Invitación no encontrada o ya no es válida');
//       }

//       const session = db.client.startSession();

//       try {
//         await session.withTransaction(async () => {
//           // Actualizar el estado de la invitación
//           await db
//             .collection('invitaciones')
//             .updateOne(
//               { _id: invitacion._id },
//               { $set: { estado: 'ACEPTADA', fechaAceptacion: new Date() } },
//             );

//           // Agregar el usuario a la empresa
//           await db
//             .collection('empresas')
//             .updateOne(
//               { _id: invitacion.empresaId },
//               { $addToSet: { usuarios: new ObjectId(decodedToken.id) } },
//             );

//           // Obtener el nombre de la empresa
//           const empresa = await db
//             .collection('empresas')
//             .findOne({ _id: invitacion.empresaId });
//           if (!empresa) {
//             throw new Error('Empresa no encontrada');
//           }

//           // Actualizar el documento del usuario para incluir la nueva empresa
//           await db.collection('usuarios').updateOne(
//             { _id: new ObjectId(decodedToken.id) },
//             {
//               $addToSet: {
//                 empresas: {
//                   _id: invitacion.empresaId,
//                   nombre: empresa.nombre,
//                 },
//               },
//             },
//           );
//         });

//         console.log('Transacción completada exitosamente');
//         return {
//           success: true,
//           message: 'Invitación aceptada exitosamente',
//         };
//       } catch (error) {
//         console.error('Error al aceptar la invitación:', error);
//         return {
//           success: false,
//           message:
//             'Error al procesar la invitación: ' + (error as Error).message,
//         };
//       } finally {
//         await session.endSession();
//       }
//     },
//   },
//   Empresa: {
//     usuarios: async (empresa, _, { db }) => {
//       return await db
//         .collection('usuarios')
//         .find({ _id: { $in: empresa.usuarios } })
//         .toArray();
//     },
//   },
//   Subscription: {
//     invitacionEmpresaRecibida: {
//       subscribe: withFilter(
//         (_, __, { pubsub }) =>
//           pubsub.asyncIterator(['INVITACION_EMPRESA_RECIBIDA']),
//         async (payload, variables, { db, token }) => {
//           try {
//             const decodedToken = verifyToken(token);
//             if (!decodedToken || !decodedToken.id) {
//               console.log('Token inválido o no presente');
//               return false;
//             }

//             const usuario = await db
//               .collection('usuarios')
//               .findOne({ _id: new ObjectId(decodedToken.id) });

//             if (!usuario) {
//               return false;
//             }

//             return payload.invitacionEmpresaRecibida.email === usuario.email;
//           } catch (error) {
//             console.error('Error al procesar la suscripción:', error);
//             return false;
//           }
//         },
//       ),
//     },
//   },
// };

// export default empresaResolvers;
