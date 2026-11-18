import { createRemoteJWKSet, jwtVerify } from 'jose';

const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Cache-Control': 'no-store'
};

function reply(body, status = 200) {
  return Response.json(body, { status, headers: cors });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method !== 'POST') return reply({ error: 'Método não permitido.' }, 405);
    const token = request.headers.get('Authorization')?.match(/^Bearer (\S+)$/)?.[1];
    if (!token) return reply({ error: 'Autenticação necessária.' }, 401);

    try {
      const { payload } = await jwtVerify(token, googleKeys, {
        issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
        audience: env.FIREBASE_PROJECT_ID,
        algorithms: ['RS256']
      });
      if (payload.email !== env.ADMIN_EMAIL || payload.email_verified !== true || !payload.sub) {
        return reply({ error: 'Acesso não autorizado.' }, 403);
      }
    } catch {
      return reply({ error: 'Sessão inválida ou expirada.' }, 401);
    }

    if (!env.CLOUDINARY_API_KEY || !env.CLOUDINARY_API_SECRET) {
      return reply({ error: 'Serviço de imagens não configurado.' }, 503);
    }
    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'gestao-estoque-bagaco';
    const value = `folder=${folder}&timestamp=${timestamp}${env.CLOUDINARY_API_SECRET}`;
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value));
    const signature = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    return reply({ timestamp, folder, signature, apiKey: env.CLOUDINARY_API_KEY, cloudName: env.CLOUDINARY_CLOUD_NAME });
  }
};
