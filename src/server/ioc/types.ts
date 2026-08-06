export type IocType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export interface ProviderResult {
  name: string;
  verdict: Verdict;
  detail: string;
  // true kalau provider GAGAL memberi penilaian (network/API error) -- beda dari
  // "tidak ada data" yang wajar (mis. VT 404 = belum pernah dilaporkan). Dipakai
  // aggregate supaya kegagalan tidak menghasilkan verdict "clean" palsu.
  error?: boolean;
}

// Batas jumlah IOC per sekali submit di bulk checker. Frontend mengirimnya
// bertahap per chunk kecil (lihat bulk-checker.astro), jadi batas Cloudflare
// Workers (~50 subrequest per invocation) bukan lagi penentu angka ini --
// yang membatasi tinggal kuota/rate limit provider (terutama VirusTotal).
export const MAX_BULK_ITEMS = 200;
