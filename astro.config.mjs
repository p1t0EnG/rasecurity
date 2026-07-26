import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';

// https://docs.astro.build/en/guides/integrations-guide/cloudflare/
export default defineConfig({
  output: 'server', // wajib 'server' karena kita butuh API routes (login, IOC check) yang jalan di edge
  adapter: cloudflare({
    platformProxy: {
      enabled: true, // bikin D1/KV bindings bisa diakses saat `astro dev` di local
    },
  }),
  build: {
    // Semua <style> jadi file CSS eksternal, TIDAK ada inline <style>. Ini penting untuk
    // CSP: kalau ada inline <style>, Astro menaruh hash-nya di `style-src`, dan begitu ada
    // hash, browser mengabaikan 'unsafe-inline' -> atribut style="" inline (dipakai banyak
    // di markup: display:none dll) ikut terblokir. Tanpa inline <style>, style-src cukup
    // 'self' 'unsafe-inline' dan atribut style bekerja normal.
    inlineStylesheets: 'never',
  },
  // Content-Security-Policy: Astro otomatis meng-hash setiap inline <script>/<style>
  // yang dia render (SHA-256) dan menaruh policy-nya via <meta>. Ini bikin
  // `script-src` bisa ketat (tanpa 'unsafe-inline') walau app punya banyak inline
  // script (login, logout, reports, dll). Header non-CSP (X-Frame-Options dst.)
  // tetap dipasang di src/middleware.ts karena <meta> CSP tidak mendukungnya.
  experimental: {
    csp: {
      directives: [
        "default-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'", // fetch browser hanya ke /api; VT/OTX/MXToolbox dipanggil server-side
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'", // anti-clickjacking (Astro emit CSP sebagai header, jadi ini efektif)
      ],
      // Script bundel Astro same-origin (/_astro/*.js) -- selain hash inline, izinkan 'self'
      scriptDirective: {
        resources: ["'self'"],
      },
      // <style> di-hash otomatis; 'unsafe-inline' untuk elemen <style> lain yang mungkin muncul
      styleDirective: {
        resources: ["'self'", "'unsafe-inline'"],
      },
    },
  },
});
