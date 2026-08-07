import { isValidIoc } from './validate';

// Ekstraksi IOC dari teks dokumen threat intel (mis. Daily Threat Intel Report .docx).
// Dokumen semacam itu men-defang IOC-nya (contoh: `mora1987[.]work[.]gd`, `hxxps://...`)
// supaya tidak bisa diklik/resolve tanpa sengaja -- jadi sebelum diklasifikasi,
// setiap kandidat harus di-refang dulu.

export interface ExtractedIocs {
  md5: string[];
  sha1: string[];
  sha256: string[];
  ip: string[];
  domain: string[];
  url: string[];
  email: string[];
  other: string[]; // email subject / nama attachment -- tetap IOC, tapi tidak bisa dicek ke provider
  mode: 'section' | 'fulltext';
  total: number;
}

export function refang(s: string): string {
  return s
    .replace(/\[\.\]/g, '.')
    .replace(/\(\.\)/g, '.')
    .replace(/\{\.\}/g, '.')
    .replace(/\bhxxps:\/\//gi, 'https://')
    .replace(/\bhxxp:\/\//gi, 'http://')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\[@\]/g, '@');
}

const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i;

type Bucket = Exclude<keyof ExtractedIocs, 'mode' | 'total'>;

// Nama file (mis. "Laporan_Q3.xls") cocok dengan pola domain karena ekstensinya
// mirip TLD -- daftar ini mencegahnya salah masuk kategori Domain.
//
// PENTING: hanya berisi ekstensi yang BUKAN TLD asli. Ekstensi yang sekaligus TLD
// sengaja TIDAK dimasukkan -- terutama `.com` (file COM warisan DOS, tapi juga TLD
// paling umum) dan `.pub`, plus .zip .mov .app .dev .sh .pl .py .md .ai .ps .one
// .cab .tv -- karena domain phishing seperti "invoice.zip" itu nyata dan tidak boleh
// ikut terbuang. Untuk kasus itu, konteks sub-judul (lihat SUBHEAD_CONTEXT) yang
// memutuskan.
const FILE_EXTENSIONS = new Set([
  // dokumen & perkantoran
  'doc', 'docx', 'docm', 'dot', 'dotx', 'xls', 'xlsx', 'xlsm', 'xlsb', 'xlt', 'xltx',
  'ppt', 'pptx', 'pptm', 'pps', 'ppsx', 'pdf', 'rtf', 'odt', 'ods', 'odp',
  'csv', 'tsv', 'txt', 'log', 'vsd', 'mpp',
  // arsip
  'rar', 'tar', 'gz', 'tgz', 'xz', 'iso', 'img', 'arj', 'lzh', 'ace', 'zipx',
  // executable / installer / script
  'exe', 'dll', 'sys', 'msi', 'msix', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'hta', 'scr', 'pif', 'cpl', 'ocx', 'jar', 'class', 'apk', 'ipa',
  'dmg', 'deb', 'rpm', 'elf', 'bin', 'lnk', 'chm', 'reg',
  // web / kode / konfigurasi
  'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'jspx', 'cgi', 'css', 'json', 'xml',
  'yml', 'yaml', 'ini', 'cfg', 'conf', 'sql', 'db', 'sqlite', 'dat', 'tmp', 'bak',
  // email & kontak
  'eml', 'msg', 'pst', 'ost', 'vcf', 'ics',
  // media & gambar
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico', 'webp', 'tif', 'tiff',
  'avi', 'mkv', 'wav', 'flac', 'wmv', 'mpeg', 'mpg', 'webm',
]);

function fileExtensionOf(value: string): string | null {
  const idx = value.lastIndexOf('.');
  if (idx < 1) return null;
  return value.slice(idx + 1).toLowerCase();
}

function looksLikeFileName(value: string): boolean {
  const ext = fileExtensionOf(value);
  return ext !== null && FILE_EXTENSIONS.has(ext);
}

// Konteks dari sub-judul di blok IOC. Ini sinyal paling kuat: nilai di bawah
// "Email attachment/link" pasti nama file/URL, bukan domain -- termasuk untuk
// ekstensi yang kebetulan juga TLD (mis. "Invoice.zip").
type SubheadContext = 'hash' | 'network' | 'email' | 'file' | 'subject';

function classifyValue(value: string, context?: SubheadContext): { bucket: Bucket; value: string } | null {
  // Buang tanda baca akhir kalimat yang sering nempel di IOC dalam prosa ("...co." dsb.)
  const v = refang(value).replace(/[.,;:]+$/, '').trim();
  if (!v || /^n\/?a$/i.test(v)) return null;

  // Subject email = teks bebas, jangan pernah ditafsirkan sebagai IOC teknis
  if (context === 'subject') return { bucket: 'other', value: v };

  if (isValidIoc(v, 'hash')) {
    const bucket = v.length === 32 ? 'md5' : v.length === 40 ? 'sha1' : 'sha256';
    return { bucket, value: v.toLowerCase() };
  }
  if (isValidIoc(v, 'url')) return { bucket: 'url', value: v };
  if (EMAIL_RE.test(v)) return { bucket: 'email', value: v.toLowerCase() };
  if (isValidIoc(v, 'ip')) return { bucket: 'ip', value: v };

  // Di bawah sub-judul attachment, sisa nilai = nama file (bukan domain)
  if (context === 'file') return { bucket: 'other', value: v };

  if (isValidIoc(v, 'domain')) {
    // "Laporan_Q3.xls" -> nama file, bukan domain
    if (looksLikeFileName(v)) return { bucket: 'other', value: v };
    return { bucket: 'domain', value: v.toLowerCase() };
  }
  return { bucket: 'other', value: v };
}

// Format laporan threat intel: blok IOC diapit header "Indicator of compromise"
// dan section berikutnya (Analyst Opinion / Recommendation / Source / Appendix).
const SECTION_START = /^indicator[s]? of compromise$/i;
const SECTION_END = /^(analyst opinion|recommendation and controls|source|appendix)$/i;
// Sub-judul di dalam blok IOC -> konteks yang dipakai classifyValue.
const SUBHEAD_CONTEXT: Record<string, SubheadContext> = {
  'md5': 'hash',
  'sha-1': 'hash',
  'sha1': 'hash',
  'sha-256': 'hash',
  'sha256': 'hash',
  'domain/ip': 'network',
  'domain': 'network',
  'ip': 'network',
  'url': 'network',
  'email address': 'email',
  'email subject': 'subject',
  'email attachment/link': 'file',
  'email attachment': 'file',
  'attachment/link': 'file',
  'attachment': 'file',
  'file name': 'file',
  'filename': 'file',
};

function emptyResult(mode: ExtractedIocs['mode']): ExtractedIocs {
  return { md5: [], sha1: [], sha256: [], ip: [], domain: [], url: [], email: [], other: [], mode, total: 0 };
}

function pushUnique(result: ExtractedIocs, seen: Set<string>, bucket: Bucket, value: string): void {
  const key = `${bucket}:${value}`;
  if (seen.has(key)) return;
  seen.add(key);
  result[bucket].push(value);
  result.total++;
}

function stripBullet(line: string): string {
  // Penanda angka ("1. item") hanya di-strip kalau diikuti spasi -- tanpa syarat itu,
  // oktet pertama IP ("195.133.67.35") ikut termakan karena mirip penanda list.
  return line.replace(/^\s*(?:[•▪‣·*-]\s*|\d+[.)]\s+)/, '').trim();
}

function extractFromSections(text: string): ExtractedIocs {
  const result = emptyResult('section');
  const seen = new Set<string>();
  let inSection = false;
  let context: SubheadContext | undefined;

  for (const rawLine of text.split('\n')) {
    const line = stripBullet(rawLine);
    if (SECTION_START.test(line)) {
      inSection = true;
      context = undefined;
      continue;
    }
    if (inSection && SECTION_END.test(line)) {
      inSection = false;
      context = undefined;
      continue;
    }
    if (!inSection || !line) continue;

    // Baris sub-judul tidak ikut diekstrak, tapi menentukan konteks baris di bawahnya
    const subhead = SUBHEAD_CONTEXT[line.toLowerCase()];
    if (subhead) {
      context = subhead;
      continue;
    }

    const ioc = classifyValue(line, context);
    if (ioc) pushUnique(result, seen, ioc.bucket, ioc.value);
  }
  return result;
}

// Fallback untuk dokumen tanpa header "Indicator of compromise": pindai seluruh teks.
// Hash & email diambil apa adanya; domain/IP/URL hanya diambil kalau ditulis defanged
// ([.] atau hxxp) -- itu tanda eksplisit "ini IOC", bukan sekadar link/nama file di prosa.
function extractFromFullText(text: string): ExtractedIocs {
  const result = emptyResult('fulltext');
  const seen = new Set<string>();

  for (const match of text.match(/\b[a-f0-9]{64}\b/gi) ?? []) {
    pushUnique(result, seen, 'sha256', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-f0-9]{40}\b/gi) ?? []) {
    pushUnique(result, seen, 'sha1', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-f0-9]{32}\b/gi) ?? []) {
    pushUnique(result, seen, 'md5', match.toLowerCase());
  }
  for (const match of text.match(/\b[a-z0-9._%+-]+(?:@|\[@\])[a-z0-9.\-\[\]]+/gi) ?? []) {
    const ioc = classifyValue(match);
    if (ioc?.bucket === 'email') pushUnique(result, seen, 'email', ioc.value);
  }
  // Token defanged: mengandung [.] atau diawali hxxp(s)
  for (const match of text.match(/\bhxxps?:\/\/\S+|\S*\[\.\]\S*/gi) ?? []) {
    const ioc = classifyValue(match.replace(/[.,;:)\]"']+$/, ''));
    if (ioc && (ioc.bucket === 'ip' || ioc.bucket === 'domain' || ioc.bucket === 'url')) {
      pushUnique(result, seen, ioc.bucket, ioc.value);
    }
  }
  return result;
}

export function extractIocs(text: string): ExtractedIocs {
  const hasIocSections = text.split('\n').some((line) => SECTION_START.test(stripBullet(line)));
  return hasIocSections ? extractFromSections(text) : extractFromFullText(text);
}

export const BUCKET_LABELS: Record<Bucket, string> = {
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  ip: 'IP Address',
  domain: 'Domain',
  url: 'URL',
  email: 'Email Address',
  other: 'Lainnya (subject/attachment)',
};

export const BUCKET_ORDER: Bucket[] = ['md5', 'sha1', 'sha256', 'ip', 'domain', 'url', 'email', 'other'];

// Nilai yang bisa langsung dicek lewat bulk checker (hash/IP/domain/URL ke
// VT/AbuseIPDB/OTX, email ke MXToolbox + VT/OTX via domain-nya).
// Subject/nama attachment tidak didukung provider mana pun, jadi tidak ikut.
export function checkableValues(result: ExtractedIocs): string[] {
  return [
    ...result.md5,
    ...result.sha1,
    ...result.sha256,
    ...result.ip,
    ...result.domain,
    ...result.url,
    ...result.email,
  ];
}

// --- Query Splunk untuk threat hunting ---
// Index mengikuti environment SOC tim: fwpaloalto (log firewall Palo Alto) untuk
// IOC network, symantec (log endpoint) untuk hash file, wineventlog untuk nama file.
// Query berupa pencarian frasa OR di _raw supaya bisa langsung dipakai tanpa perlu
// tahu nama field hasil ekstraksi masing-masing sourcetype.

export interface SplunkQuery {
  label: string;
  description: string;
  query: string;
}

function splEscape(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function toOrList(values: string[]): string {
  return values.map((v) => `"${splEscape(v)}"`).join(' OR ');
}

// Khusus file yang bisa dieksekusi/di-load (exe, dll, script, installer, dst.) --
// itu yang relevan di-hunting sebagai jejak eksekusi di Windows Event Log.
// Arsip/dokumen (zip, pdf, docx) sengaja tidak ikut ke query wineventlog.
const EXEC_FILE_RE =
  /\.(exe|dll|sys|com|scr|pif|msi|msix?|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|lnk|chm|jar|cpl|ocx)$/i;

function isExecutableFileName(value: string): boolean {
  return !/\s/.test(value) && !value.includes('/') && EXEC_FILE_RE.test(value);
}

// Nama file executable dikumpulkan dari bucket "other" (nama attachment) + nama
// file di ujung path URL (mis. .../loader.js atau .../install.res.1033.dll).
function collectExecutableFileNames(result: ExtractedIocs): string[] {
  const names = new Set<string>();
  for (const value of result.other) {
    if (isExecutableFileName(value)) names.add(value);
  }
  for (const url of result.url) {
    try {
      const segments = new URL(url).pathname.split('/');
      const last = decodeURIComponent(segments[segments.length - 1] ?? '');
      if (isExecutableFileName(last)) names.add(last);
    } catch {
      // URL tidak valid -- lewati
    }
  }
  return [...names];
}

export function buildSplunkQueries(result: ExtractedIocs): SplunkQuery[] {
  const queries: SplunkQuery[] = [];

  const network = [...result.ip, ...result.domain, ...result.url];
  if (network.length > 0) {
    queries.push({
      label: 'Network -- Palo Alto Firewall',
      description: `${result.ip.length} IP, ${result.domain.length} domain, ${result.url.length} URL di index=fwpaloalto`,
      query: `index=fwpaloalto (${toOrList(network)})`,
    });
  }

  const hashes = [...result.md5, ...result.sha1, ...result.sha256];
  if (hashes.length > 0) {
    queries.push({
      label: 'File Hash -- Symantec Endpoint',
      description: `${hashes.length} hash (MD5/SHA-1/SHA-256) di index=symantec`,
      query: `index=symantec (${toOrList(hashes)})`,
    });
  }

  const fileNames = collectExecutableFileNames(result);
  if (fileNames.length > 0) {
    queries.push({
      label: 'Nama File Executable -- Windows Event Log',
      description: `${fileNames.length} file executable/script di index=wineventlog`,
      query: `index=wineventlog (${toOrList(fileNames)})`,
    });
  }

  return queries;
}

export function buildExportText(result: ExtractedIocs, sourceName: string): string {
  let out = `# Rekan Siber - IOC Extractor\n# Sumber: ${sourceName}\n# Diekstrak: ${new Date().toISOString()}\n# Total: ${result.total} IOC\n\n`;
  for (const bucket of BUCKET_ORDER) {
    const values = result[bucket];
    if (!values.length) continue;
    out += `# ${BUCKET_LABELS[bucket]} (${values.length})\n${values.join('\n')}\n\n`;
  }
  return out;
}
