// libs/unalib.js
// Versión reforzada: valida imágenes/videos, phone, YouTube y BLOQUEA intentos de XSS devolviendo kind:'blocked'

const MAX_LEN = 2000;
const IMG_EXT = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.avif'];
const VID_EXT = ['.mp4', '.webm', '.ogg', '.m4v', '.mov'];

/* ---------------- helpers ---------------- */
function normalizeStr(value) {
  if (typeof value !== 'string') return '';
  let s = value.trim().replace(/&amp;/g, '&');
  s = s.replace(/[\u0000-\u0008\u000B-\u000C\u000E-\u001F\u007F]/g, '');
  if (s.length > MAX_LEN) s = s.slice(0, MAX_LEN);
  return s;
}
function asURL(value) {
  const s = normalizeStr(value);
  try {
    const u = new URL(s);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (u.username || u.password) return null;
    if (/^(javascript|data|vbscript|file|blob):/i.test(s)) return null;
    return u;
  } catch { return null; }
}
function hasAnyExt(pathname, extList) {
  const p = pathname.toLowerCase();
  return extList.some(ext => p.endsWith(ext));
}
function unwrapKnownImageRedirect(urlStr) {
  const u = asURL(urlStr);
  if (!u) return null;
  const host = u.hostname.toLowerCase();
  if (host.includes('bing.com') && u.searchParams.has('mediaurl')) {
    try { return new URL(u.searchParams.get('mediaurl')); } catch { return null; }
  }
  if (host.includes('google.') && u.searchParams.has('imgurl')) {
    try { return new URL(u.searchParams.get('imgurl')); } catch { return null; }
  }
  return null;
}
function stripTags(text) {
  return String(text).replace(/<\/?[^>]+>/g, '');
}
function escapeText(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* ---------------- validadores públicos ---------------- */
function is_valid_phone(phone) {
  if (typeof phone !== 'string') return false;
  const s = phone.trim();
  if (!s) return false;
  if (/[^0-9+\-\s().]/.test(s)) return false;
  const digitCount = (s.match(/\d/g) || []).length;
  if (digitCount < 7 || digitCount > 15) return false;
  if ((s.match(/\+/g) || []).length > 1) return false;
  if (s.includes('+') && !s.startsWith('+')) return false;
  return true;
}

function is_valid_url_image(urlStr) {
  const unwrapped = unwrapKnownImageRedirect(urlStr);
  const u = unwrapped || asURL(urlStr);
  return u ? hasAnyExt(u.pathname, IMG_EXT) : false;
}

function is_valid_url_video(urlStr) {
  const u = asURL(urlStr);
  return u ? hasAnyExt(u.pathname, VID_EXT) : false;
}

function is_valid_yt_video(urlStr) {
  const u = asURL(urlStr);
  if (!u) return false;
  const host = u.hostname.toLowerCase();
  return host.includes('youtube.com') || host.includes('youtu.be');
}

function getYTVideoId(urlStr) {
  const u = asURL(urlStr);
  if (!u) return null;
  if (u.hostname.toLowerCase().includes('youtu.be')) {
    return u.pathname.split('/').filter(Boolean)[0] || null;
  }
  if (u.searchParams.has('v')) return u.searchParams.get('v');
  const parts = u.pathname.split('/');
  const idx = parts.findIndex(p => p === 'embed' || p === 'v');
  if (idx >= 0 && parts[idx+1]) return parts[idx+1];
  return null;
}

/* ---------------- validateMessage (estricto: bloquea XSS) ----------------
   Devuelve JSON string con:
   - { nombre, color, kind: 'image'|'video'|'youtube'|'text' }
   - Si detecta patrones maliciosos devuelve { nombre, color, kind: 'blocked' }
*/
function validateMessage(msg) {
  const safeDefault = JSON.stringify({ nombre:'Anónimo', color:'#000', kind:'text', text:'' });
  if (!msg || typeof msg !== 'string') return safeDefault;

  try {
    const obj = JSON.parse(msg) || {};
    const nombre = typeof obj.nombre === 'string' ? stripTags(normalizeStr(obj.nombre)).slice(0,50) : 'Anónimo';
    const color  = typeof obj.color  === 'string' ? normalizeStr(obj.color) : '#000';
    const rawIn  = typeof obj.mensaje === 'string' ? obj.mensaje : '';
    const raw = normalizeStr(rawIn);

    /* ---------- DETECCIÓN ESTRICTA: BLOQUEAR si coincide ---------- */
    // 1) cualquier tag HTML
    const hasTag = /<\/?[a-z][\s\S]*?>/i.test(raw);
    // 2) atributos on* (onerror=, onclick=, onload=, etc.)
    const hasOnAttr = /on[a-z]+\s*=/i.test(raw);
    // 3) schemas peligrosos al inicio
    const hasDangerScheme = /^\s*(javascript:|data:|vbscript:|file:|blob:)/i.test(raw);
    // 4) snippets JS que suelen indicar payloads
    const hasXssSnippets = /(document\.cookie|innerHTML|eval\s*\(|window\.location|localStorage\.[\w]+)/i.test(raw);

    if (hasTag || hasOnAttr || hasDangerScheme || hasXssSnippets) {
      return JSON.stringify({ nombre, color, kind: 'blocked' });
    }

    /* ---------- LÓGICA NORMAL (si no fue bloqueado) ---------- */
    if (is_valid_url_image(raw)) {
      const unwrapped = unwrapKnownImageRedirect(raw);
      const url = (unwrapped ? unwrapped.toString() : asURL(raw).toString());
      return JSON.stringify({ nombre, color, kind:'image', url });
    }

    if (is_valid_url_video(raw)) {
      return JSON.stringify({ nombre, color, kind:'video', url: asURL(raw).toString() });
    }

    if (is_valid_yt_video(raw)) {
      const id = getYTVideoId(raw);
      if (id) return JSON.stringify({ nombre, color, kind:'youtube', videoId: id });
    }

    // texto plano seguro
    return JSON.stringify({ nombre, color, kind:'text', text: escapeText(stripTags(raw)) });

  } catch (e) {
    // si parse falla, analiza raw y potencialmente bloquea
    const raw2 = normalizeStr(String(msg));
    if ( /<\/?[a-z][\s\S]*?>/i.test(raw2) || /on[a-z]+\s*=/i.test(raw2) || /^\s*(javascript:|data:)/i.test(raw2) ) {
      return JSON.stringify({ nombre:'Anónimo', color:'#000', kind:'blocked' });
    }
    return JSON.stringify({ nombre:'Anónimo', color:'#000', kind:'text', text: escapeText(stripTags(raw2)) });
  }
}

/* ---------------- exports ---------------- */
module.exports = {
  is_valid_phone,
  is_valid_url_image,
  is_valid_url_video,
  is_valid_yt_video,
  getYTVideoId,
  validateMessage
};
