## Descripción General del Funcionamiento

### 1. Perspectiva del Cliente Final

#### 1.1 Acceso al Software
1. **Registro y Activación**
   - Cliente recibe licencia con código de activación
   - Descarga el software del producto
   - Ingresa código de activación
   - Sistema verifica:
     - Validez de la licencia
     - Dominios permitidos
     - Límites de conexión

2. **Uso del Software**
   - Sistema verifica continuamente:
     - Estado de la licencia
     - Dominio de ejecución
     - Número de conexiones activas
     - Hash del ejecutable

3. **Actualizaciones**
   - Notificaciones automáticas de nuevas versiones
   - Verificación de integridad mediante hash
   - Control de versiones deprecated

4. **Gestión de Licencia**
   - Visualización de estado
   - Monitoreo de conexiones activas
   - Alertas de vencimiento
   - Opciones de renovación

### 2. Perspectiva del Administrador

#### 2.1 Inicio en el Sistema
1. **Registro de Administrador**
   - Crear cuenta con datos básicos
   - Verificación por OTP (teléfono)
   - Recibe créditos iniciales gratuitos 
   - Acceso al panel de administración

2. **Gestión de Créditos**
   - Monitoreo de saldo disponible
   - Recarga de créditos
   - Visualización de consumo

#### 2.2 Creación y Gestión de Productos

##### A. Opción "PARA EMPRESA"
1. **Proceso de Creación**
   - Verificar existencia de empresa
   - Consumo de créditos
   - Configuración inicial:
     - Detalles del producto
     - Plataformas soportadas
     - Primera versión con hash
   - Asignación de usuarios:
     - ADMIN_EMPRESA
     - EMPLEADO

2. **Gestión de Usuarios Empresa**
   - Invitar nuevos usuarios
   - Asignar roles y permisos
   - Control de accesos
   - Eliminación de usuarios

##### B. Opción "PARA MÍ"
1. **Creación Personal**
   - Consumo de créditos
   - Configuración del producto
   - Administración directa

2. **Gestión de Colaboradores**
   - Invitar usuarios específicos
   - Asignar roles:
     - ADMIN_PRODUCTO
     - EMPLEADO
   - Capacidad de:
     - Transferir administración
     - Gestionar colaboradores
     - Auto-eliminación con transferencia

##### C. Opción "EMPRESA Y USUARIO ESPECÍFICO"
1. **Configuración Especial**
   - Seleccionar empresa existente
   - Elegir usuario específico
   - Asignar permisos limitados
   - Usuario solo ve este producto

#### 2.3 Gestión de Versiones
1. **Subida de Versiones**
   - Archivo ejecutable
   - Generación de hash
   - Notas de cambios
   - Control de estado

2. **Administración de Versiones**
   - Activar/Deprecar versiones
   - Notificaciones automáticas
   - Control de actualizaciones

#### 2.4 Gestión de Licencias
1. **Creación de Licencias** (Consume Créditos)
   - Configuración:
     - Email del cliente
     - Conexiones máximas
     - Fecha de vencimiento
     - Dominios permitidos
     - Reglas personalizadas

2. **Monitoreo de Licencias**
   - Estado actual
   - Conexiones activas
   - Uso por dominio
   - Actividad de usuarios

### 3. Sistema de Notificaciones en Tiempo Real

#### 3.1 Notificaciones para Clientes
- Vencimiento próximo
- Nuevas versiones
- Límite de conexiones
- Estados de licencia

#### 3.2 Notificaciones para Administradores
- Uso de créditos
- Nuevas invitaciones
- Cambios en productos
- Actividad de licencias

### 4. Flujos de Asociación y Permisos

#### 4.1 Asociación a Empresas
1. **Proceso de Invitación**
   ```
   Administrador → Envía Invitación → Usuario
                                   → Estados:
                                     └── PENDIENTE
                                     └── ACEPTADA
                                     └── RECHAZADA
                                     └── CANCELADA
   ```

2. **Niveles de Acceso**
   ```
   Empresa
   └── ADMIN_EMPRESA
       └── Gestión completa
   └── EMPLEADO
       └── Acceso limitado
   ```

#### 4.2 Asociación a Productos
1. **Tipos de Asociación**
   ```
   Producto
   └── Individual
       └── ADMIN_PRODUCTO
       └── EMPLEADO
   └── Empresa
       └── ADMIN_EMPRESA
       └── EMPLEADO
   └── Usuario Específico
       └── Acceso único
   ```

### 5. Control de Cambios y Seguridad

#### 5.1 Historial de Cambios
- Modificaciones en productos
- Cambios de administración
- Gestión de usuarios
- Actividad de licencias

#### 5.2 Verificaciones de Seguridad
- Validación de hash
- Control de dominios
- Monitoreo de conexiones
- Registro de actividades

## Reglas de Negocio Críticas

1. **Créditos y Operaciones**
   - Saldo suficiente para operaciones
   - Descuento automático
   - Control de transacciones

2. **Gestión de Productos**
   - Al menos un administrador
   - Control de versiones
   - Verificación de integridad

3. **Licencias y Control**
   - Validación en tiempo real
   - Control de conexiones
   - Restricciones de dominio

4. **Seguridad**
   - Verificación OTP
   - Control de accesos
   - Monitoreo continuo

## Diagrama de Estados Principales

```
Sistema
└── Administrador
    ├── Créditos
    │   ├── Inicial (Regalo)
    │   └── Gestión
    ├── Productos
    │   ├── Para Empresa
    │   ├── Personal
    │   └── Mixto (Empresa+Usuario)
    └── Licencias
        ├── Configuración
        ├── Monitoreo
        └── Estados

Cliente
└── Licencia
    ├── Activación
    ├── Uso
    │   ├── Conexiones
    │   └── Dominios
    └── Estados
        ├── ACTIVA
        ├── SUSPENDIDA
        ├── VENCIDA
        └── CANCELADA
```


```markmap
---
markmap:
  height: 1069
---

# Sistema de Gestión de Software

## Usuarios
### Administrador
#### Registro
- Datos básicos
- Verificación OTP
- Créditos iniciales gratuitos

#### Sistema de Créditos
- Saldo disponible
- Consumo por operaciones
- Recarga
- Historial

#### Gestión
- Crear productos
- Administrar empresas
- Gestionar usuarios
- Monitoreo general

### Cliente Final
#### Registro
- Datos básicos
- Activación de licencia
- Verificación de dominio

#### Uso
- Acceso al software
- Control de conexiones
- Actualizaciones
- Soporte

## Productos
### Tipos de Creación
#### Para Empresa
- Asociación a empresa existente
- Múltiples usuarios
- Roles empresariales
- Control compartido

#### Para Mí (Personal)
- Gestión individual
- Invitación a colaboradores
- Transferencia de administración
- Control total

#### Empresa + Usuario Específico
- Acceso limitado
- Usuario específico
- Permisos personalizados
- Visibilidad restringida

### Versiones
#### Control
- Número de versión
- Hash de verificación
- Archivo ejecutable
- Notas de cambios

#### Estados
- Activa
- Deprecated
- Archivada

#### Actualizaciones
- Notificación automática
- Verificación de integridad
- Control de distribución

### Licencias
#### Configuración
- Email del cliente
- Conexiones máximas
- Fecha de vencimiento
- Dominios permitidos

#### Estados
- Activa
- Suspendida
- Vencida
- Cancelada

#### Monitoreo
- Conexiones activas
- IP y MAC
- Dispositivos
- Actividad

## Empresas
### Gestión
#### Usuarios
- Roles
- Permisos
- Invitaciones

#### Productos
- Asignación
- Control
- Monitoreo

### Roles
#### Admin Empresa
- Control total
- Gestión de usuarios
- Administración de productos

#### Empleado
- Acceso limitado
- Funciones específicas
- Permisos restringidos

## Seguridad
### Verificación
- OTP
- Hash de software
- Dominios permitidos
- Control de licencias

### Monitoreo
- Conexiones activas
- Actividad de usuarios
- Uso de licencias
- Registro de cambios

## Notificaciones
### Tiempo Real
#### Administrador
- Uso de créditos
- Nuevas invitaciones
- Cambios en productos
- Estado de licencias

#### Cliente
- Vencimiento de licencia
- Nuevas versiones
- Límite de conexiones
- Actualizaciones

### Sistema
- Subscriptions GraphQL
- Alertas automáticas
- Mensajes de estado
- Comunicaciones importantes

## Roles y Permisos
### Producto
- ADMIN_PRODUCTO
- EMPLEADO

### Empresa
- ADMIN_EMPRESA
- EMPLEADO

### Sistema
- SUPER_ADMIN
- ADMIN
- CLIENTE
```

Visita [este enlace](./markmap.html)para visualizar el diagrama en formato interactivo.