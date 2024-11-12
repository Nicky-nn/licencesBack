export interface Usuario {
  id: string;
  nombre: string;
  apellido: string;
  email: string;
  password: string;
  telefono?: string;
  rol: RolUsuario;
  estado: EstadoUsuario;
  creditos: number;
  empresas: Empresa[];
  productos: Producto[];
}

export enum RolUsuario {
  SUPER_ADMIN = 'SUPER_ADMIN',
  ADMIN = 'ADMIN',
  CLIENTE = 'CLIENTE',
}

export enum EstadoUsuario {
  ACTIVO = 'ACTIVO',
  INACTIVO = 'INACTIVO',
}

export interface Empresa {
  id: string;
  nombre: string;
  usuarios: Usuario[];
  productos: Producto[];
}

export interface Producto {
  id: string;
  nombre: string;
  reglas: string[];
  imagen?: string;
  clave: string;
  version: string;
  archivo?: string;
  plataforma: Plataforma[];
  hash: string;
  maxConexiones: number;
  correoAsociado: string;
  idUnico: string;
  versionesAnteriores: VersionProducto[];
  clientes: Cliente[];
  empresa: Empresa;
}

export enum Plataforma {
  WINDOWS = 'WINDOWS',
  MAC = 'MAC',
  LINUX = 'LINUX',
  IOS = 'IOS',
  ANDROID = 'ANDROID',
}

export interface VersionProducto {
  version: string;
  fechaCreacion: string;
  cambios?: string;
}

export interface Cliente {
  id: string;
  email: string;
  password: string;
  productos: Producto[];
  dispositivos: Dispositivo[];
}

export interface Dispositivo {
  id: string;
  macAddress: string;
  ipAddress: string;
  ultimaConexion: string;
}

export interface Notificacion {
  id: string;
  mensaje: string;
  fecha: string;
}

export interface CrearUsuarioInput {
  nombre: string;
  apellido: string;
  email: string;
  password: string;
  telefono?: string;
  rol: RolUsuario;
}

export interface ActualizarUsuarioInput {
  nombre?: string;
  apellido?: string;
  email?: string;
  password?: string;
  telefono?: string;
}

export interface CrearEmpresaInput {
  nombre: string;
}

export interface ActualizarEmpresaInput {
  nombre?: string;
}

export interface CrearProductoInput {
  nombre: string;
  reglas: string[];
  imagen?: File;
  clave: string;
  version: string;
  archivo?: File;
  plataforma: Plataforma[];
  maxConexiones: number;
  correoAsociado: string;
  empresaId?: string;
}

export interface ActualizarProductoInput {
  nombre?: string;
  reglas?: string[];
  imagen?: File;
  clave?: string;
  version?: string;
  archivo?: File;
  plataforma?: Plataforma[];
  maxConexiones?: number;
  correoAsociado?: string;
}

export interface RegistrarClienteInput {
  email: string;
  password: string;
  productoId: string;
}

export interface DispositivoInput {
  macAddress: string;
  ipAddress: string;
}

export interface AuthResponse {
  token: string;
  usuario: Usuario;
}

export interface AuthClienteResponse {
  token: string;
  cliente: Cliente;
}

export interface InvitacionEmpresaResponse {
  success: boolean;
  message: string;
  invitacion?: InvitacionEmpresa;
}

export interface InvitacionEmpresa {
  id: string;
  email: string;
  empresa: Empresa;
  estado: EstadoInvitacion;
}

export interface VerificacionOTPResult {
  success: boolean;
  message: string;
  usuario?: Usuario;
}

export enum EstadoInvitacion {
  PENDIENTE = 'PENDIENTE',
  ACEPTADA = 'ACEPTADA',
  RECHAZADA = 'RECHAZADA',
}

export interface InvitacionProductoResponse {
  success: boolean;
  message: string;
  invitacion?: InvitacionProducto;
}

export interface InvitacionProducto {
  id: string;
  email: string;
  producto: Producto;
  estado: EstadoInvitacion;
}
