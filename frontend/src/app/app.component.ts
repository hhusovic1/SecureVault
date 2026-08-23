import { CommonModule } from '@angular/common';
import { AfterViewInit, Component, ElementRef, ViewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { BrutePoint, FileMeta, SecurevaultService, SymmetricResult } from './securevault.service';

interface Step { label: string; state: 'pending' | 'done' | 'fail'; }

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent implements AfterViewInit {
  @ViewChild('benchCanvas') benchCanvas!: ElementRef<HTMLCanvasElement>;
  @ViewChild('bruteCanvas') bruteCanvas!: ElementRef<HTMLCanvasElement>;

  // --- sesija ---
  steps: Step[] = [];
  handshaking = false;
  error = '';

  // --- trezor ---
  files: FileMeta[] = [];
  selectedFile: File | null = null;
  uploading = false;

  // --- benchmark ---
  benchAlg = 'AES';
  benchKey = 256;
  benchSize = 1024;
  benchReps = 10;
  benchRows: SymmetricResult[] = [];
  benchBusy = false;
  private benchData: { label: string; value: number }[] = [];

  // --- brute-force ---
  bfMin = 8;
  bfMax = 22;
  bruteBusy = false;

  constructor(public sv: SecurevaultService) {}

  ngAfterViewInit(): void {
    this.clearCanvas(this.benchCanvas);
    this.clearCanvas(this.bruteCanvas);
  }

  get sessionShort(): string {
    return this.sv.sessionId ? this.sv.sessionId.slice(0, 8) : '';
  }

  // ---------------- 1. HANDSHAKE ----------------
  async doHandshake(): Promise<void> {
    this.error = '';
    this.handshaking = true;
    this.steps = [
      { label: 'Dohvat certifikata servera', state: 'pending' },
      { label: 'Razmjena efemernih ECDH ključeva (init)', state: 'pending' },
      { label: 'Verifikacija digitalnog potpisa servera', state: 'pending' },
      { label: 'Izvođenje zajedničkog AES-256 ključa (HKDF)', state: 'pending' },
      { label: 'Slanje "Finished" poruke (finish)', state: 'pending' },
    ];
    try {
      await this.sv.handshake((i, ok) => (this.steps[i].state = ok ? 'done' : 'fail'));
      await this.refresh();
    } catch (e: any) {
      this.error = 'Handshake: ' + (e?.message ?? e);
    } finally {
      this.handshaking = false;
    }
  }

  // ---------------- 2. TREZOR ----------------
  onFileSelected(ev: Event): void {
    const input = ev.target as HTMLInputElement;
    this.selectedFile = input.files?.[0] ?? null;
  }

  async doUpload(): Promise<void> {
    if (!this.selectedFile) { this.error = 'Izaberi fajl.'; return; }
    this.error = '';
    this.uploading = true;
    try {
      await this.sv.upload(this.selectedFile);
      this.selectedFile = null;
      await this.refresh();
    } catch (e: any) {
      this.error = e?.message ?? String(e);
    } finally {
      this.uploading = false;
    }
  }

  async refresh(): Promise<void> {
    if (!this.sv.established) return;
    this.files = await this.sv.listFiles();
  }

  async download(f: FileMeta): Promise<void> {
    try {
      await this.sv.download(f.fileId, f.originalName);
    } catch (e: any) {
      this.error = e?.message ?? String(e);
    }
  }

  formatBytes(n: number): string {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(2) + ' MB';
  }

  // ---------------- 3. BENCHMARK ----------------
  async runBench(): Promise<void> {
    this.error = '';
    this.benchBusy = true;
    try {
      const r = await this.sv.benchmarkSymmetric(this.benchAlg, this.benchKey, this.benchSize, this.benchReps);
      this.benchRows.unshift(r);
      this.benchData.push({ label: `${r.algorithm}-${r.keySizeBits}/${r.dataSizeKB}KB`, value: r.encryptThroughputMBs });
      this.drawBars(this.benchCanvas, this.benchData, 'MB/s');
    } catch (e: any) {
      this.error = 'Benchmark: ' + (e?.message ?? e);
    } finally {
      this.benchBusy = false;
    }
  }

  clearBench(): void {
    this.benchRows = [];
    this.benchData = [];
    this.clearCanvas(this.benchCanvas);
  }

  // ---------------- 4. BRUTE-FORCE ----------------
  async runBrute(): Promise<void> {
    this.error = '';
    this.bruteBusy = true;
    try {
      const rows = await this.sv.bruteScaling(this.bfMin, this.bfMax);
      this.drawLine(this.bruteCanvas, rows.map((r: BrutePoint) => ({ x: r.keyBits, y: r.elapsedMs })),
        'bitovi ključa', 'vrijeme (ms, log)');
    } catch (e: any) {
      this.error = 'Brute-force: ' + (e?.message ?? e);
    } finally {
      this.bruteBusy = false;
    }
  }

  // ---------------- canvas grafovi ----------------
  private clearCanvas(ref: ElementRef<HTMLCanvasElement>): void {
    const c = ref?.nativeElement;
    if (c) c.getContext('2d')!.clearRect(0, 0, c.width, c.height);
  }

  private drawBars(ref: ElementRef<HTMLCanvasElement>, data: { label: string; value: number }[], unit: string): void {
    const c = ref.nativeElement, ctx = c.getContext('2d')!;
    ctx.clearRect(0, 0, c.width, c.height);
    if (!data.length) return;
    const pad = 50, max = Math.max(...data.map(d => d.value)) * 1.15;
    const bw = (c.width - pad * 2) / data.length;
    ctx.strokeStyle = '#334155'; ctx.font = '11px sans-serif';
    ctx.beginPath(); ctx.moveTo(pad, 10); ctx.lineTo(pad, c.height - pad); ctx.lineTo(c.width - 10, c.height - pad); ctx.stroke();
    data.forEach((d, i) => {
      const h = (d.value / max) * (c.height - pad - 20);
      const x = pad + i * bw + bw * 0.15, y = c.height - pad - h;
      const grad = ctx.createLinearGradient(0, y, 0, c.height - pad);
      grad.addColorStop(0, '#38bdf8'); grad.addColorStop(1, '#0ea5e9');
      ctx.fillStyle = grad; ctx.fillRect(x, y, bw * 0.7, h);
      ctx.fillStyle = '#e2e8f0'; ctx.textAlign = 'center';
      ctx.fillText(d.value.toFixed(0), x + bw * 0.35, y - 5);
      ctx.save(); ctx.translate(x + bw * 0.35, c.height - pad + 8); ctx.rotate(-0.5);
      ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'right'; ctx.fillText(d.label, 0, 0); ctx.restore();
    });
    ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText(unit, 8, 16);
  }

  private drawLine(ref: ElementRef<HTMLCanvasElement>, pts: { x: number; y: number }[], xl: string, yl: string): void {
    const c = ref.nativeElement, ctx = c.getContext('2d')!;
    ctx.clearRect(0, 0, c.width, c.height);
    if (!pts.length) return;
    const pad = 55;
    const xs = pts.map(p => p.x), ys = pts.map(p => Math.max(p.y, 0.0001));
    const xmin = Math.min(...xs), xmax = Math.max(...xs);
    const ymin = Math.log10(Math.min(...ys)), ymax = Math.log10(Math.max(...ys) * 1.3);
    const X = (v: number) => pad + (xmax === xmin ? 0.5 : (v - xmin) / (xmax - xmin)) * (c.width - pad - 20);
    const Y = (v: number) => (c.height - pad) - (ymax === ymin ? 0.5 : (Math.log10(v) - ymin) / (ymax - ymin)) * (c.height - pad - 20);
    ctx.strokeStyle = '#334155'; ctx.beginPath();
    ctx.moveTo(pad, 10); ctx.lineTo(pad, c.height - pad); ctx.lineTo(c.width - 10, c.height - pad); ctx.stroke();
    ctx.strokeStyle = '#38bdf8'; ctx.lineWidth = 2; ctx.beginPath();
    pts.forEach((p, i) => { const x = X(p.x), y = Y(Math.max(p.y, 0.0001)); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.stroke();
    ctx.fillStyle = '#38bdf8';
    pts.forEach(p => { ctx.beginPath(); ctx.arc(X(p.x), Y(Math.max(p.y, 0.0001)), 3.5, 0, 7); ctx.fill(); });
    ctx.fillStyle = '#e2e8f0'; ctx.font = '11px sans-serif'; ctx.textAlign = 'center';
    pts.forEach(p => ctx.fillText(String(p.x), X(p.x), c.height - pad + 16));
    ctx.fillStyle = '#94a3b8'; ctx.textAlign = 'left'; ctx.fillText(yl, 8, 16);
    ctx.textAlign = 'right'; ctx.fillText(xl, c.width - 10, c.height - pad + 34);
  }
}
