import axios from 'axios';
import { env } from '../config/env';

export const sendWhatsAppMessage = async (
  to: string,
  codigoVerificacion: string, // Código de verificación
  url: string, // URL para el botón
): Promise<void> => {
  console.log(
    'Enviando mensaje de WhatsApp usando template de verificación:',
    to,
  );
  try {
    await axios.post(
      'https://graph.facebook.com/v20.0/345938235279065/messages',
      {
        messaging_product: 'whatsapp',
        to: to,
        type: 'template',
        template: {
          name: 'verificacion', // Nombre del template
          language: {
            code: 'es_AR', // Español Argentina
          },
          components: [
            {
              type: 'body',
              parameters: [
                {
                  type: 'text',
                  text: codigoVerificacion, // Código de verificación en el cuerpo del mensaje
                },
              ],
            },
            {
              type: 'button',
              sub_type: 'url',
              index: 0,
              parameters: [
                {
                  type: 'payload',
                  payload: url, // URL requerida para el botón
                },
              ],
            },
          ],
        },
      },
      {
        headers: {
          Authorization: `Bearer ${env.WHATSAPP_API_KEY}`,
          'Content-Type': 'application/json',
        },
      },
    );
  } catch (error: any) {
    console.error(
      'Error al enviar mensaje de WhatsApp con template:',
      error.response?.data || error.message,
    );
    throw new Error('No se pudo enviar el mensaje de WhatsApp con template');
  }
};
