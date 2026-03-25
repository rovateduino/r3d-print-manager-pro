import { createCipheriv, createHash, randomBytes } from 'crypto';
import axios from 'axios';
import firebaseConfig from '../firebase-applet-config.json';

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || firebaseConfig.projectId;
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
const DB_ID = process.env.DB_ID || firebaseConfig.firestoreDatabaseId || '(default)';

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getToken() {
  try {
    if (cachedToken && Date.now() < tokenExpiry) return cachedToken;
    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: FIREBASE_CLIENT_EMAIL,
      sub: FIREBASE_CLIENT_EMAIL,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    };
    const sHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const sPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const { sign } = await import('crypto');
    const signature = sign('sha256', Buffer.from(`${sHeader}.${sPayload}`), FIREBASE_PRIVATE_KEY!).toString('base64url');
    const res = await axios.post('https://oauth2.googleapis.com/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${sHeader}.${sPayload}.${signature}`,
    });
    cachedToken = res.data.access_token;
    tokenExpiry = Date.now() + 3500 * 1000;
    return cachedToken;
  } catch (error: any) {
    console.error('Error getting Firebase token:', error.response?.data || error.message);
    throw error;
  }
}

function buildFirestoreUrl(path: string) {
  return `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/${DB_ID}/documents/${path}`;
}

async function fsList(collection: string): Promise<any[]> {
  try {
    const token = await getToken();
    const res = await axios.get(buildFirestoreUrl(collection), { headers: { Authorization: `Bearer ${token}` } });
    return (res.data.documents || []).map((doc: any) => ({ id: doc.name.split('/').pop(), ...decodeFields(doc.fields || {}) }));
  } catch (e: any) {
    if (e.response?.status === 404) return [];
    console.error(`[fsList] ${collection} error:`, e.response?.data || e.message);
    return [];
  }
}

async function fsGet(collection: string, id: string): Promise<any> {
  try {
    const token = await getToken();
    const res = await axios.get(buildFirestoreUrl(`${collection}/${id}`), { headers: { Authorization: `Bearer ${token}` } });
    if (!res.data.fields) return null;
    return { id, ...decodeFields(res.data.fields) };
  } catch (e: any) {
    if (e.response?.status === 404) return null;
    console.error(`[fsGet] ${collection}/${id} error:`, e.response?.data || e.message);
    return null;
  }
}

async function fsSet(collection: string, id: string, data: any): Promise<any> {
  try {
    const token = await getToken();
    const fields = Object.keys(data);
    const mask = fields.map((f: string) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join('&');
    const url = `${buildFirestoreUrl(`${collection}/${id}`)}?${mask}`;
    const res = await axios.patch(url, { fields: encodeFields(data) }, { headers: { Authorization: `Bearer ${token}` } });
    return decodeFields(res.data.fields || {});
  } catch (e: any) {
    console.error(`[fsSet] ${collection}/${id} error:`, e.response?.data || e.message);
    throw e;
  }
}

async function fsCreate(collection: string, id: string, data: any): Promise<any> {
  try {
    const token = await getToken();
    const url = `${buildFirestoreUrl(collection)}?documentId=${encodeURIComponent(id)}`;
    const res = await axios.post(url, { fields: encodeFields(data) }, { headers: { Authorization: `Bearer ${token}` } });
    return decodeFields(res.data.fields || {});
  } catch (e: any) {
    console.error(`[fsCreate] ${collection}/${id} error:`, e.response?.data || e.message);
    throw e;
  }
}

async function fsDelete(collection: string, id: string): Promise<void> {
  try {
    const token = await getToken();
    await axios.delete(buildFirestoreUrl(`${collection}/${id}`), { headers: { Authorization: `Bearer ${token}` } });
  } catch (e: any) {
    if (e.response?.status === 404) return;
    console.error(`[fsDelete] ${collection}/${id} error:`, e.response?.data || e.message);
    throw e;
  }
}

function encodeFields(obj: any): any {
  const fields: any = {};
  for (const [key, val] of Object.entries(obj)) {
    if (val === undefined) continue;
    if (val === null) { fields[key] = { nullValue: null }; continue; }
    if (typeof val === 'string') fields[key] = { stringValue: val };
    else if (typeof val === 'number') fields[key] = { doubleValue: val };
    else if (typeof val === 'boolean') fields[key] = { booleanValue: val };
    else if (Array.isArray(val)) fields[key] = { arrayValue: { values: val.map((v: any) => encodeFields({ temp: v }).temp) } };
    else if (typeof val === 'object') fields[key] = { mapValue: { fields: encodeFields(val) } };
    else fields[key] = { nullValue: null };
  }
  return fields;
}

function decodeFields(fields: any): any {
  if (!fields) return {};
  const obj: any = {};
  for (const [key, val] of Object.entries(fields)) {
    const v: any = val;
    if (!v) { obj[key] = null; continue; }
    if ('stringValue' in v) obj[key] = v.stringValue;
    else if ('doubleValue' in v) obj[key] = Number(v.doubleValue);
    else if ('integerValue' in v) obj[key] = Number(v.integerValue);
    else if ('booleanValue' in v) obj[key] = v.booleanValue;
    else if ('nullValue' in v) obj[key] = null;
    else if ('arrayValue' in v) obj[key] = (v.arrayValue?.values || []).map((item: any) => decodeFields({ temp: item }).temp);
    else if ('mapValue' in v) obj[key] = decodeFields(v.mapValue?.fields || {});
    else obj[key] = null;
  }
  return obj;
}

async function sendEmail(to: string, subject: string, html: string): Promise<void> {
  if (!process.env.RESEND_API_KEY) { console.warn('RESEND_API_KEY ausente'); return; }
  try {
    await axios.post('https://api.resend.com/emails', { from: 'R3D Pro <contato@r3dprintmanagerpro.com.br>', to, subject, html }, { headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` } });
  } catch (e: any) { console.error('Erro Resend:', e.response?.data || e.message); }
}

const asaasUrl = () => process.env.ASAAS_ENV === 'production' ? 'https://api.asaas.com/v3' : 'https://sandbox.asaas.com/api/v3';

function generateLicenseKey(payload: any): string {
  const secret = process.env.KEYGEN_SECRET || 'R3D_SECRET_KEY_2026_XPTO_MANAGER';
  const key = createHash('sha256').update(secret).digest();
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

function verifyKeygenToken(authHeader: string | undefined): boolean {
  if (!authHeader?.startsWith('Bearer ')) return false;
  try {
    const obj = JSON.parse(Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf8'));
    return obj.type === 'keygen' && obj.exp > Date.now();
  } catch { return false; }
}

function generateKeygenToken(): string {
  return Buffer.from(JSON.stringify({ type: 'keygen', exp: Date.now() + 8 * 60 * 60 * 1000 })).toString('base64');
}

const keygenFailedAttempts = new Map<string, { count: number; blockedUntil: number }>();

export default async function handler(req: any, res: any) {
  try {
    const url = req.url || '';
    const method = req.method || 'GET';
    console.log(`[API] ${method} ${url}`);
    const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';
    const isAdmin = req.headers['x-admin-password'] === ADMIN_PASS;

    // ── Health ────────────────────────────────────────────────────────────────
    if (url.includes('/api/health')) {
      try {
        await getToken();
        return res.json({ status: 'ok', firebase: true, dbId: DB_ID, asaasEnv: process.env.ASAAS_ENV || 'sandbox' });
      } catch (e: any) {
        return res.json({ status: 'ok', firebase: false, error: e.message });
      }
    }

    // ── Keygen: Auth ──────────────────────────────────────────────────────────
    if (url.includes('/api/keygen/auth') && method === 'POST') {
      const ip = String(req.headers['x-forwarded-for'] || 'unknown').split(',')[0].trim();
      const attempt = keygenFailedAttempts.get(ip);
      if (attempt?.blockedUntil && attempt.blockedUntil > Date.now()) {
        return res.status(429).json({ authorized: false, error: `IP bloqueado. Tente em ${Math.ceil((attempt.blockedUntil - Date.now()) / 60000)} min.` });
      }
      const KEYGEN_MASTER = process.env.KEYGEN_MASTER_PASSWORD || 'R3D@Master2025!';
      if (req.body?.password === KEYGEN_MASTER) {
        keygenFailedAttempts.delete(ip);
        return res.json({ authorized: true, token: generateKeygenToken() });
      }
      const cur = keygenFailedAttempts.get(ip) || { count: 0, blockedUntil: 0 };
      cur.count += 1;
      if (cur.count >= 3) { cur.blockedUntil = Date.now() + 5 * 60 * 1000; cur.count = 0; }
      keygenFailedAttempts.set(ip, cur);
      return res.json({ authorized: false, error: 'Senha incorreta.' });
    }

    // ── Keygen: Verificar token ───────────────────────────────────────────────
    if (url.includes('/api/keygen/generate') && method === 'POST') {
      if (!verifyKeygenToken(req.headers['authorization'])) return res.status(401).json({ error: 'Token inválido' });
      return res.json({ ok: true });
    }

    // ── Keygen: Listar histórico ──────────────────────────────────────────────
    if (url.includes('/api/keygen/history') && !url.includes('/import') && !url.includes('/delete') && method === 'GET') {
      if (!verifyKeygenToken(req.headers['authorization'])) return res.status(401).json({ error: 'Token inválido' });
      const records = await fsList('keygen_history');
      const grouped: any = {};
      for (const r of records) {
        const hwid = r.hwid || r.id;
        if (!grouped[hwid]) grouped[hwid] = { hwid, totalKeys: 0, lastGenerated: r.generated_at, lastType: r.type, keys: [] };
        grouped[hwid].totalKeys += 1;
        grouped[hwid].keys.push({ id: r.id, type: r.type, generated: r.generated_at, expires: r.expires || null, notes: r.notes || '', nonce: r.nonce || '' });
        if (r.generated_at && new Date(r.generated_at) > new Date(grouped[hwid].lastGenerated)) { grouped[hwid].lastGenerated = r.generated_at; grouped[hwid].lastType = r.type; }
      }
      return res.json(grouped);
    }

    // ── Keygen: Salvar histórico ──────────────────────────────────────────────
    if (url.includes('/api/keygen/history') && !url.includes('/import') && !url.includes('/delete') && method === 'POST') {
      if (!verifyKeygenToken(req.headers['authorization'])) return res.status(401).json({ error: 'Token inválido' });
      const { hwid, type, nonce, generated_at, expires, notes } = req.body || {};
      if (!hwid || !type || !nonce) return res.status(400).json({ error: 'hwid, type e nonce são obrigatórios' });
      await fsSet('keygen_history', `${hwid}_${nonce}`, { hwid, type, nonce, generated_at: generated_at || new Date().toISOString(), expires: expires || null, notes: notes || '' });
      return res.json({ success: true });
    }

    // ── Keygen: Importar histórico ────────────────────────────────────────────
    if (url.includes('/api/keygen/history/import') && method === 'POST') {
      if (!verifyKeygenToken(req.headers['authorization'])) return res.status(401).json({ error: 'Token inválido' });
      const records = req.body;
      if (!Array.isArray(records)) return res.status(400).json({ error: 'Formato inválido' });
      let imported = 0; let skipped = 0;
      for (const r of records) {
        if (!r.hwid || !r.nonce) { skipped++; continue; }
        const existing = await fsGet('keygen_history', `${r.hwid}_${r.nonce}`);
        if (existing) { skipped++; continue; }
        await fsSet('keygen_history', `${r.hwid}_${r.nonce}`, { hwid: r.hwid, type: r.type || 'trial', nonce: r.nonce, generated_at: r.generated_at || new Date().toISOString(), expires: r.expires || null, notes: r.notes || '' });
        imported++;
      }
      return res.json({ success: true, imported, skipped });
    }

    // ── Keygen: Deletar histórico ─────────────────────────────────────────────
    if (url.includes('/api/keygen/history/delete') && method === 'POST') {
      if (!verifyKeygenToken(req.headers['authorization'])) return res.status(401).json({ error: 'Token inválido' });
      const records = await fsList('keygen_history');
      for (const r of records) { try { await fsDelete('keygen_history', r.id); } catch { /* continua */ } }
      return res.json({ success: true, deleted: records.length });
    }

    // ── Validar cupom ─────────────────────────────────────────────────────────
    if (url.includes('/api/cupom/validar') && method === 'GET') {
      const codigo = req.query?.codigo || url.split('codigo=')[1]?.split('&')[0];
      if (!codigo) return res.status(400).json({ message: 'Código ausente' });
      const coupon = await fsGet('cupons', String(codigo).toUpperCase());
      if (!coupon || !coupon.ativo) return res.status(404).json({ message: 'Cupom inválido ou inativo' });
      if (coupon.limite_usos && coupon.usos >= coupon.limite_usos) return res.status(400).json({ message: 'Limite de usos atingido' });
      if (coupon.validade && new Date(coupon.validade) < new Date()) return res.status(400).json({ message: 'Cupom expirado' });
      return res.json(coupon);
    }

    // ── Admin: Listar cupons ──────────────────────────────────────────────────
    if (url.includes('/api/admin/cupons') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      return res.json(await fsList('cupons'));
    }

    // ── Admin: Criar cupom ────────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/criar') && method === 'POST') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const data = req.body || {};
      const codigo = String(data.codigo || '').toUpperCase().trim();
      if (!codigo) return res.status(400).json({ message: 'Código é obrigatório' });
      await fsSet('cupons', codigo, { codigo, tipo: data.tipo || 'PERCENTUAL', valor: Number(data.valor) || 0, afiliado_nome: data.afiliado_nome || '', afiliado_email: data.afiliado_email || '', afiliado_telefone: data.afiliado_telefone || '', limite_usos: Number(data.limite_usos) || 0, validade: data.validade || '', ativo: data.ativo !== undefined ? data.ativo : true, usos: 0, vendas: [], criado_em: new Date().toISOString() });
      if (data.afiliado_email) {
        await sendEmail(data.afiliado_email, 'Seu cupom de afiliado foi criado!', `<div style="font-family:Arial,sans-serif"><h2 style="color:#C67D3D">Olá ${data.afiliado_nome}! 🎉</h2><p>Seu cupom <strong>${codigo}</strong> foi criado!</p><p>Desconto: ${data.tipo === 'PERCENTUAL' ? `${data.valor}%` : `R$ ${Number(data.valor).toFixed(2)}`}</p></div>`);
      }
      return res.json({ success: true });
    }

    // ── Admin: Atualizar cupom ────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && !url.includes('/criar') && method === 'PUT') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const id = url.split('/api/admin/cupom/')[1]?.split('?')[0];
      const existing = await fsGet('cupons', id);
      await fsSet('cupons', id, { ...(existing || {}), ...req.body });
      return res.json({ success: true });
    }

    // ── Admin: Deletar cupom ──────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && !url.includes('/criar') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Não autorizado' });
      let id = url.split('/api/admin/cupom/')[1]?.split('?')[0];
      if (id) id = decodeURIComponent(id).trim().replace(/\/$/, '');
      if (!id) return res.status(400).json({ message: 'ID é obrigatório' });
      await fsDelete('cupons', id);
      return res.json({ success: true });
    }

    // ── Asaas: Criar cliente ──────────────────────────────────────────────────
    if (url.includes('/api/asaas/customer') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/customers`, req.body, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao criar cliente' }); }
    }

    // ── Asaas: Criar pagamento ────────────────────────────────────────────────
    if (url.includes('/api/asaas/payment') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/payments`, req.body, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao processar pagamento' }); }
    }

    // ── Asaas: PIX QR Code ────────────────────────────────────────────────────
    if (url.includes('/api/asaas/pix-qrcode') && method === 'GET') {
      const paymentId = req.query?.paymentId || url.split('paymentId=')[1]?.split('&')[0];
      if (!paymentId) return res.status(400).json({ message: 'paymentId ausente' });
      try {
        const r = await axios.get(`${asaasUrl()}/payments/${paymentId}/pixQrCode`, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json({ message: 'Erro ao buscar QR Code PIX' }); }
    }

    // ── Asaas: Webhook ────────────────────────────────────────────────────────
    if (url.includes('/api/asaas/webhook') && method === 'POST') {
      const body = req.body;
      const event = Array.isArray(body) ? body[0] : body;
      const payment = event?.payment;
      const webhookToken = req.headers['asaas-access-token'];
      const isSimulated = webhookToken === 'SIMULATED_TOKEN';
      const configuredToken = process.env.ASAAS_WEBHOOK_TOKEN;
      console.log(`[Webhook] Evento: ${event?.event}, Pagamento: ${payment?.id}`);
      if (configuredToken && !isSimulated && webhookToken !== configuredToken) return res.status(401).json({ message: 'Unauthorized' });
      if (!payment) return res.status(400).json({ message: 'Missing payment' });

      let generatedCode = null;
      try {
        await fsSet('payments', payment.id, { paymentId: payment.id, status: payment.status, event: event.event, value: payment.value, customer: payment.customer, billingType: payment.billingType || '', installmentNumber: payment.installmentNumber || 1, processedAt: new Date().toISOString(), externalReference: payment.externalReference || '', isSimulated });

        if (event.event === 'PAYMENT_CONFIRMED' || event.event === 'PAYMENT_RECEIVED') {
          const extRef = payment.externalReference || '';
          const parts = extRef.split(':');
          const hasCoupon = parts[0] === 'COUPON';
          const couponCode = hasCoupon ? parts[1] : '';
          const planName = hasCoupon ? parts.slice(2, parts.length - 1).join(' ') : parts.slice(1, parts.length - 1).join(' ');
          const isFirstInstallment = (payment.installmentNumber || 1) === 1;

          let customerEmail = '';
          let customerName = '';
          if (isSimulated) { customerEmail = payment.customerEmail || 'teste@exemplo.com'; customerName = payment.customerName || 'Cliente Teste'; }
          else {
            try {
              const cr = await axios.get(`${asaasUrl()}/customers/${payment.customer}`, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
              customerEmail = cr.data.email || ''; customerName = cr.data.name || '';
            } catch (e) { console.error('Erro ao buscar cliente:', e); }
          }

          if (customerEmail && isFirstInstallment) {
            await fsSet('users', customerEmail, { email: customerEmail, isPro: true, subscriptionId: payment.installment || payment.id, plano: planName, updatedAt: new Date().toISOString() });
            const existingActivation = await fsGet('activations_by_payment', payment.id);
            if (existingActivation?.code) {
              generatedCode = existingActivation.code;
            } else {
              const code = `R3D-ACT-${randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g)?.join('-')}`;
              generatedCode = code;
              const expirationDate = new Date();
              expirationDate.setDate(expirationDate.getDate() + 7);
              await fsSet('activations', code, { code, paymentId: payment.id, email: customerEmail, name: customerName, plano: planName || 'PRO', status: 'PENDING', createdAt: new Date().toISOString(), expiresAt: expirationDate.toISOString() });
              await fsSet('activations_by_payment', payment.id, { code });
              console.log(`[Activation] Código gerado: ${code} para ${customerEmail}`);
              try {
                const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#C67D3D">Parabéns pela sua compra! 🎉</h2><p>Olá ${customerName}, seu pagamento foi confirmado.</p><div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0"><h1 style="color:#C67D3D;font-size:32px;margin:10px 0">${code}</h1></div><ol><li>Baixe o app: <a href="https://r3dprintmanagerpro.com.br/api/download">Clique aqui</a></li><li>Abra e insira o código acima.</li><li>O sistema vincula ao seu computador.</li></ol><p style="color:#ff4444"><strong>Atenção:</strong> Este código expira em 7 dias.</p></div>`;
                await sendEmail(customerEmail, 'Seu código de ativação R3D Print Manager Pro', emailHtml);
                if (isSimulated && process.env.ADMIN_EMAIL && process.env.ADMIN_EMAIL !== customerEmail) await sendEmail(process.env.ADMIN_EMAIL, `[SIMULAÇÃO] Código - ${customerEmail}`, emailHtml);
              } catch (emailErr) { console.error('Erro ao enviar e-mail:', emailErr); }
            }
          }

          if (couponCode && isFirstInstallment) {
            const coupon = await fsGet('cupons', couponCode.toUpperCase());
            if (coupon) {
              const existingVendas = Array.isArray(coupon.vendas) ? coupon.vendas : [];
              const installmentId = payment.installment || payment.id;
              const jaProcessado = existingVendas.some((v: any) => v.installmentId === installmentId || v.paymentId === payment.id);
              if (!jaProcessado) {
                const novosUsos = (Number(coupon.usos) || 0) + 1;
                await fsSet('cupons', coupon.codigo || couponCode.toUpperCase(), { ...coupon, usos: novosUsos, vendas: [...existingVendas, { paymentId: payment.id, installmentId, plano: planName || 'N/A', valor: payment.value, cliente: customerName, email: customerEmail, afiliado: coupon.afiliado_nome || '', data: new Date().toISOString() }] });
                if (coupon.afiliado_email) await sendEmail(coupon.afiliado_email, `🎉 Nova venda com seu cupom ${coupon.codigo}!`, `<div style="font-family:Arial,sans-serif"><h2 style="color:#C67D3D">Nova venda! 🚀</h2><p>Olá ${coupon.afiliado_nome}! Cupom: ${coupon.codigo} | Plano: ${planName || 'N/A'} | Valor: R$ ${payment.value?.toFixed(2)} | Usos: ${novosUsos}</p></div>`);
                if (process.env.ADMIN_EMAIL) await sendEmail(process.env.ADMIN_EMAIL, `Nova venda com cupom — ${coupon.codigo}`, `<div style="font-family:Arial,sans-serif"><p>Cupom: ${coupon.codigo} | Afiliado: ${coupon.afiliado_nome} | Cliente: ${customerName} | Valor: R$ ${payment.value?.toFixed(2)}</p></div>`);
              }
            }
          }
        }
        if (isSimulated) return res.json({ status: 'success', message: 'Simulação processada', code: generatedCode });
        return res.status(200).json({ status: 'success' });
      } catch (e: any) { console.error('[Webhook] Erro:', e.message); return res.status(500).json({ error: e.message }); }
    }

    // ── Status do usuário ─────────────────────────────────────────────────────
    if (url.includes('/api/user/status/') && method === 'GET') {
      const email = decodeURIComponent(url.split('/api/user/status/')[1] || '');
      const data = await fsGet('users', email);
      return res.json(data || { isPro: false });
    }

    // ── Trial por HWID (BLOQUEIO DUPLO) ───────────────────────────────────────
    if (url.includes('/api/license/trial-hwid') && method === 'POST') {
      try {
        const { hwid, email } = req.body || {};
        console.log('[Trial-HWID] Recebido:', { hwid, email });
        if (!hwid) return res.status(400).json({ message: 'HWID é obrigatório' });
        if (!email) return res.status(400).json({ message: 'E-mail é obrigatório para ativar o teste gratuito' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: 'E-mail inválido' });
        if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(hwid)) return res.status(400).json({ message: 'Formato de HWID inválido. Use: 00000000-0000-0000-0000-000000000000' });
        const trialHistory = await fsGet('trials_hwid', hwid);
        if (trialHistory) return res.status(400).json({ message: 'Este computador já utilizou o período de teste gratuito. Adquira um plano para continuar.' });
        const emailHistory = await fsGet('trials_email', email.toLowerCase());
        if (emailHistory) return res.status(400).json({ message: 'Este e-mail já utilizou o período de teste gratuito. Adquira um plano para continuar.' });
        const existingLicense = await fsGet('licenses', hwid);
        if (existingLicense) return res.status(400).json({ message: existingLicense.plano === 'Trial' ? 'Este computador já possui um teste ativo.' : 'Este computador já possui uma licença ativa.' });
        const expiration = new Date();
        expiration.setDate(expiration.getDate() + 7);
        const licenseKey = generateLicenseKey({ hwid, type: 'Trial', issued: new Date().toISOString(), expiration: expiration.toISOString(), version: 1, nonce: randomBytes(8).toString('hex') });
        await fsCreate('licenses', hwid, { hwid, plano: 'Trial', licenseKey, email: email.toLowerCase(), activatedAt: new Date().toISOString(), expiration: expiration.toISOString() });
        await fsCreate('trials_hwid', hwid, { hwid, email: email.toLowerCase(), usedAt: new Date().toISOString(), expiration: expiration.toISOString() });
        await fsCreate('trials_email', email.toLowerCase(), { hwid, email: email.toLowerCase(), usedAt: new Date().toISOString(), expiration: expiration.toISOString() });
        console.log(`[Trial-HWID] Ativado: ${hwid} / ${email}`);
        try { await sendEmail(email, 'Seu Teste Gratuito R3D Pro foi ativado! 🚀', `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#C67D3D">Teste ativado! 🎉</h2><p>Seu período de <strong>7 dias</strong> está ativo.</p><div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;margin:20px 0"><p style="color:#999;font-size:12px;margin:0 0 8px">CHAVE DE LICENÇA</p><p style="color:#C67D3D;font-family:monospace;font-size:11px;word-break:break-all;margin:0">${licenseKey}</p><hr style="border:1px solid #333;margin:16px 0"/><p style="color:#999;font-size:12px;margin:0 0 4px">EXPIRA EM</p><p style="color:white;font-weight:bold;margin:0">${expiration.toLocaleDateString('pt-BR')}</p></div><p style="color:#ff4444;font-size:12px">⚠️ Cada computador e e-mail pode usar o teste apenas uma vez.</p></div>`); } catch { /* silencioso */ }
        if (process.env.ADMIN_EMAIL) { try { await sendEmail(process.env.ADMIN_EMAIL, `Novo Trial HWID ativado`, `<p><strong>HWID:</strong> ${hwid}</p><p><strong>E-mail:</strong> ${email}</p><p><strong>Expira:</strong> ${expiration.toLocaleDateString('pt-BR')}</p>`); } catch { /* silencioso */ } }
        return res.json({ success: true, plano: 'Trial', expiration: expiration.toISOString(), licenseKey, diasRestantes: 7 });
      } catch (e: any) { console.error('[Trial-HWID] ERRO:', e.message); return res.status(500).json({ message: 'Erro interno ao ativar trial', error: e.message }); }
    }

    // ── Ativar Licença ────────────────────────────────────────────────────────
    if (url.includes('/api/license/activate') && method === 'POST') {
      const { code, activationCode, hwid } = req.body || {};
      const finalCode = code || activationCode;
      if (!finalCode || !hwid) return res.status(400).json({ message: 'Código e HWID são obrigatórios' });
      if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(hwid)) return res.status(400).json({ message: 'Formato de HWID inválido' });
      const activation = await fsGet('activations', String(finalCode).toUpperCase());
      if (!activation) return res.status(404).json({ message: 'Código de ativação não encontrado' });
      if (activation.status === 'USED') return res.status(400).json({ message: 'Este código já foi utilizado' });
      if (activation.expiresAt && new Date(activation.expiresAt) < new Date()) return res.status(400).json({ message: 'Este código expirou' });
      const now = new Date(); let expiration: string | null = null;
      const plano = activation.plano || 'Mensal';
      if (plano === 'Trial') { now.setDate(now.getDate() + 7); expiration = now.toISOString(); }
      else if (plano === 'Mensal') { now.setDate(now.getDate() + 30); expiration = now.toISOString(); }
      else if (plano === 'Trimestral') { now.setDate(now.getDate() + 90); expiration = now.toISOString(); }
      else if (plano === 'Semestral') { now.setDate(now.getDate() + 180); expiration = now.toISOString(); }
      else if (plano === 'Anual') { now.setDate(now.getDate() + 365); expiration = now.toISOString(); }
      const licenseKey = generateLicenseKey({ hwid, type: plano, issued: new Date().toISOString(), expiration, version: 1, nonce: randomBytes(8).toString('hex') });
      await fsSet('activations', String(finalCode).toUpperCase(), { ...activation, status: 'USED', hwid, licenseKey, activatedAt: new Date().toISOString() });
      await fsSet('licenses', hwid, { hwid, plano, licenseKey, email: activation.email || '', activatedAt: new Date().toISOString(), expiration });
      await fsSet('logs_activation', `${Date.now()}_${hwid}`, { event: 'ACTIVATION_SUCCESS', code: finalCode, hwid, email: activation.email || '', timestamp: new Date().toISOString() });
      return res.json({ success: true, licenseKey, plano, expiration });
    }

    // ── Validar Licença ───────────────────────────────────────────────────────
    if (url.includes('/api/license/validate') && method === 'GET') {
      const hwid = req.query?.hwid || url.split('hwid=')[1]?.split('&')[0];
      if (!hwid) return res.status(400).json({ message: 'HWID ausente' });
      const license = await fsGet('licenses', hwid);
      if (!license) return res.status(404).json({ message: 'Licença não encontrada', valid: false });
      const now = new Date();
      const isExpired = license.expiration && new Date(license.expiration) < now;
      if (isExpired) return res.json({ valid: false, message: 'Sua licença expirou.', plano: license.plano, expiration: license.expiration, diasRestantes: 0 });
      let diasRestantes = 9999;
      if (license.expiration) diasRestantes = Math.max(0, Math.ceil((new Date(license.expiration).getTime() - now.getTime()) / 86400000));
      return res.json({ valid: true, plano: license.plano, expiration: license.expiration || null, diasRestantes });
    }

    // ── Recuperar Códigos ─────────────────────────────────────────────────────
    if (url.includes('/api/license/recover') && method === 'GET') {
      const email = req.query?.email || url.split('email=')[1]?.split('&')[0];
      if (!email) return res.status(400).json({ message: 'E-mail é obrigatório' });
      const allActivations = await fsList('activations');
      const userActivations = allActivations.filter((a: any) => a.email?.toLowerCase() === decodeURIComponent(email).toLowerCase());
      if (userActivations.length === 0) return res.status(404).json({ message: 'Nenhuma ativação encontrada' });
      return res.json(userActivations.map((a: any) => ({ code: a.code, status: a.status, createdAt: a.createdAt, plano: a.plano })));
    }

    // ── Trial por e-mail ──────────────────────────────────────────────────────
    if (url.includes('/api/license/trial') && !url.includes('/trial-hwid') && method === 'POST') {
      const { email, name } = req.body || {};
      if (!email) return res.status(400).json({ message: 'E-mail é obrigatório' });
      const allActivations = await fsList('activations');
      const hasTrial = allActivations.some((a: any) => a.email === email && a.plano === 'Trial');
      if (hasTrial) return res.status(400).json({ message: 'Você já solicitou um período de teste para este e-mail.' });
      const code = `R3D-TRIAL-${randomBytes(4).toString('hex').toUpperCase()}`;
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + 7);
      await fsSet('activations', code, { code, email, name: name || 'Usuário Trial', plano: 'Trial', status: 'PENDING', createdAt: new Date().toISOString(), expiresAt: expirationDate.toISOString() });
      await sendEmail(email, 'Seu código TRIAL - R3D Print Manager Pro', `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto"><h2 style="color:#C67D3D">Seu período de teste começou! 🚀</h2><div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0"><h1 style="color:#C67D3D;font-size:32px;margin:10px 0">${code}</h1></div><p>Acesse a seção de ativação no site para vincular ao seu computador.</p></div>`);
      return res.json({ success: true, message: 'Código enviado para seu e-mail!' });
    }

    // ── Admin: Listar ativações ───────────────────────────────────────────────
    if (url.includes('/api/admin/activations') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      return res.json(await fsList('activations'));
    }

    // ── Admin: Resetar ativação ───────────────────────────────────────────────
    if (url.includes('/api/admin/activation/reset/') && method === 'POST') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const code = url.split('/reset/')[1]?.split('?')[0];
      if (!code) return res.status(400).json({ message: 'Código é obrigatório' });
      const activation = await fsGet('activations', code.toUpperCase());
      if (!activation) return res.status(404).json({ message: 'Ativação não encontrada' });
      await fsSet('activations', code.toUpperCase(), { ...activation, status: 'AVAILABLE', usedAt: null, hwid: null });
      return res.json({ message: 'Ativação resetada com sucesso' });
    }

    // ── Admin: Listar licenças ────────────────────────────────────────────────
    if (url.includes('/api/admin/licenses') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      return res.json(await fsList('licenses'));
    }

    // ── Admin: Deletar licença ────────────────────────────────────────────────
    if (url.includes('/api/admin/license/delete/') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      let hwid = url.split('/delete/')[1]?.split('?')[0];
      if (hwid) hwid = decodeURIComponent(hwid).trim().replace(/\/$/, '');
      if (!hwid) return res.status(400).json({ message: 'HWID é obrigatório' });
      await fsDelete('licenses', hwid);
      return res.json({ message: 'Licença removida com sucesso' });
    }

    // ── Admin: Deletar ativação ───────────────────────────────────────────────
    if (url.includes('/api/admin/activation/delete/') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      let code = url.split('/delete/')[1]?.split('?')[0];
      if (code) code = decodeURIComponent(code).trim().replace(/\/$/, '');
      if (!code) return res.status(400).json({ message: 'Código é obrigatório' });
      await fsDelete('activations', code.toUpperCase());
      return res.json({ message: 'Ativação excluída com sucesso' });
    }

    // ── Admin: Backup Total ───────────────────────────────────────────────────
    if (url.includes('/api/admin/backup') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const [activations, licenses, cupons, payments, trialsHwid, trialsEmail] = await Promise.all([fsList('activations'), fsList('licenses'), fsList('cupons'), fsList('payments'), fsList('trials_hwid'), fsList('trials_email')]);
      return res.json({ timestamp: new Date().toISOString(), activations, licenses, cupons, payments, trialsHwid, trialsEmail });
    }

    // ── Download ──────────────────────────────────────────────────────────────
    if (url.includes('/api/download')) {
      return res.redirect(302, 'https://github.com/rovateduino/R3D-PRINT-MANAGER-PRO/releases/download/v.2_5/Setup_R3D_PrintManager_Pro.exe');
    }

    console.warn(`[API] 404: ${method} ${url}`);
    return res.status(404).json({ message: 'Not found', path: url });

  } catch (error: any) {
    console.error(`[API] Global Error:`, error.message);
    return res.status(500).json({ error: 'Internal Server Error', message: error.message });
  }
}
