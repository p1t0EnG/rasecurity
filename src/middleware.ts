import { defineMiddleware } from 'astro:middleware';

// Security header untuk semua halaman HTML (SSR). Content-Security-Policy sendiri
// di-emit oleh Astro (fitur experimental.csp di astro.config) lewat <meta>, karena
// Astro yang tahu hash tiap inline <script>/<style> yang dia render. Di sini kita
// pasang header yang TIDAK bisa lewat <meta> CSP:
//   - X-Frame-Options: anti-clickjacking (padanan frame-ancestors, yang diabaikan di <meta>)
//   - X-Content-Type-Options, Referrer-Policy, Permissions-Policy
//   - Strict-Transport-Security (production saja)
export const onRequest = defineMiddleware(async (_context, next) => {
  const response = await next();

  // Hanya sentuh response HTML -- JSON API, download PDF/XLSX, dan redirect dilewati
  // supaya Content-Type/Content-Disposition/Set-Cookie mereka tidak terganggu.
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('text/html')) {
    return response;
  }

  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // Astro menaruh hash tiap <style> di `style-src`. Begitu ada hash, browser
  // MENGABAIKAN 'unsafe-inline' -> atribut style="" inline (display:none dll) ikut
  // terblokir. `script-src` tetap dibiarkan ketat (hash Astro), tapi `style-src`
  // kita bersihkan jadi 'self' 'unsafe-inline' saja supaya atribut style bekerja.
  // (Injeksi style jauh lebih rendah risikonya dibanding injeksi script.)
  const csp = response.headers.get('content-security-policy');
  if (csp) {
    response.headers.set(
      'content-security-policy',
      csp.replace(/style-src[^;]*/i, "style-src 'self' 'unsafe-inline'"),
    );
  }

  if (import.meta.env.PROD) {
    response.headers.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }

  return response;
});
