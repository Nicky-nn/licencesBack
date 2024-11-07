# Bot de WhatsApp Multiusuario

Este proyecto implementa un sistema de bot de WhatsApp multiusuario con una arquitectura escalable, utilizando TypeScript, MongoDB, GraphQL con Apollo, y WebSocket para la gestión de códigos QR.

## Características principales

- Sistema de autenticación y autorización con roles (superadmin, admin, bot)
- Integración con WhatsApp para envío de mensajes
- GraphQL API para la gestión de usuarios, bots y empresas
- WebSocket para la transmisión segura de códigos QR
- Autenticación OTP para la creación de bots y usuarios
- Control de acceso basado en roles
- Limitación de tasa para prevenir intentos excesivos de inicio de sesión
- Asociación de administradores y bots a empresas

## Estructura del proyecto

```
src/
├── config/
│   ├── database.ts
│   ├── apollo.ts
│   └── websocket.ts
├── models/
│   ├── User.ts
│   ├── Bot.ts
│   ├── Company.ts
│   └── Session.ts
├── graphql/
│   ├── schema/
│   │   ├── user.graphql
│   │   ├── bot.graphql
│   │   └── company.graphql
│   ├── resolvers/
│   │   ├── user.ts
│   │   ├── bot.ts
│   │   └── company.ts
│   └── directives/
│       └── auth.ts
├── services/
│   ├── otp.ts
│   └── websocket.ts
├── middlewares/
│   ├── authentication.ts
│   ├── rateLimit.ts
│   └── errorHandler.ts
├── utils/
│   ├── encryption.ts
│   ├── tokenManager.ts
│   └── validators.ts
├── types/
│   ├── user.ts
│   ├── bot.ts
│   └── company.ts
├── routes/
│   ├── api.ts
│   └── websocket.ts
├── whatsapp/
│   └── whatsappService.ts
└── index.ts
```

## Configuración del proyecto

1. Clona el repositorio:
        
    Copiar código
    
    `git clone https://github.com/tu-usuario/tu-repositorio.git`
    
2. Navega al directorio del proyecto:
    
    `cd tu-repositorio`
    
3. Instala las dependencias:
    
    `npm install`
    
4. Configura las variables de entorno en el archivo `.env`.
5. Inicia el servidor en modo de desarrollo:
    
    `npm run dev`
    
## Scripts disponibles

- `npm run dev`: Inicia el servidor en modo de desarrollo
- `npm run build`: Compila el proyecto
- `npm start`: Inicia el servidor en modo de producción
- `npm run lint`: Ejecuta el linter
- `npm run format`: Formatea el código con Prettier

## Contribución

1. Haz un fork del proyecto.
2. Crea una nueva rama:
    
    `git checkout -b feature/amazing-feature`
    
3. Haz commit de tus cambios:
    
    `git commit -m 'Add some amazing feature'`
    
4. Haz push a la rama:
    
    `git push origin feature/amazing-feature`
    
5. Abre un Pull Request.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.