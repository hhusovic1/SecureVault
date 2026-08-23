package com.husovic.securevault.benchmark;

import com.husovic.securevault.benchmark.dto.AsymmetricBenchmarkResponse;
import com.husovic.securevault.benchmark.dto.SymmetricBenchmarkResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Locale;

@RestController
@RequestMapping("/api/benchmark")
@Tag(name = "Benchmark", description = "Empirijsko mjerenje performansi algoritama (Faza 3)")
public class BenchmarkController {

    private final BenchmarkService benchmarkService;
    private final BenchmarkStore store;

    public BenchmarkController(BenchmarkService benchmarkService, BenchmarkStore store) {
        this.benchmarkService = benchmarkService;
        this.store = store;
    }

    @Operation(summary = "Benchmark simetričnog algoritma (DES/3DES/AES)",
            description = "Mjeri prosječno vrijeme enkripcije/dekripcije i propusnost (MB/s) uz JVM warm-up.")
    @GetMapping("/symmetric")
    public SymmetricBenchmarkResponse symmetric(
            @RequestParam String algorithm,
            @RequestParam(defaultValue = "256") int keySize,
            @RequestParam(defaultValue = "1024") int dataSizeKB,
            @RequestParam(defaultValue = "10") int repetitions,
            @RequestParam(defaultValue = "3") int warmup) {
        return benchmarkService.runSymmetric(algorithm, keySize, dataSizeKB, repetitions, warmup);
    }

    @Operation(summary = "Benchmark asimetričnog algoritma (RSA/DH/ECDH)",
            description = "RSA: keygen + enc/dec male poruke. DH/ECDH: keygen + vrijeme cijele razmjene. "
                    + "Parametar je dužina ključa (RSA/DH) ili naziv krive (ECDH: X25519, P-256).")
    @GetMapping("/asymmetric")
    public AsymmetricBenchmarkResponse asymmetric(
            @RequestParam String algorithm,
            @RequestParam String keySize,
            @RequestParam(defaultValue = "5") int repetitions,
            @RequestParam(defaultValue = "1") int warmup) {
        return benchmarkService.runAsymmetric(algorithm, keySize, repetitions, warmup);
    }

    @Operation(summary = "Svi akumulirani rezultati (JSON)")
    @GetMapping("/results")
    public List<BenchmarkRow> results() {
        return store.all();
    }

    @Operation(summary = "Izvoz rezultata", description = "format=csv (podrazumijevano) ili format=json")
    @GetMapping("/export")
    public ResponseEntity<String> export(@RequestParam(defaultValue = "csv") String format) {
        List<BenchmarkRow> rows = store.all();
        if ("json".equalsIgnoreCase(format)) {
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"benchmark.json\"")
                    .body(toJson(rows));
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"benchmark.csv\"")
                .body(toCsv(rows));
    }

    @Operation(summary = "Briše akumulirane rezultate")
    @DeleteMapping("/results")
    public String clear() {
        return "Obrisano redova: " + store.clear();
    }

    private String toCsv(List<BenchmarkRow> rows) {
        StringBuilder sb = new StringBuilder();
        sb.append("timestamp,category,algorithm,parameter,operation,dataSizeKB,repetitions,avgMs,throughputMBs\n");
        for (BenchmarkRow r : rows) {
            sb.append(r.timestamp()).append(',')
                    .append(r.category()).append(',')
                    .append(r.algorithm()).append(',')
                    .append(r.parameter()).append(',')
                    .append(r.operation()).append(',')
                    .append(r.dataSizeKB() == null ? "" : r.dataSizeKB()).append(',')
                    .append(r.repetitions()).append(',')
                    .append(String.format(Locale.US, "%.6f", r.avgMs())).append(',')
                    .append(r.throughputMBs() == null ? "" : String.format(Locale.US, "%.6f", r.throughputMBs()))
                    .append('\n');
        }
        return sb.toString();
    }

    private String toJson(List<BenchmarkRow> rows) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < rows.size(); i++) {
            BenchmarkRow r = rows.get(i);
            sb.append("{\"timestamp\":\"").append(r.timestamp()).append("\",")
                    .append("\"category\":\"").append(r.category()).append("\",")
                    .append("\"algorithm\":\"").append(r.algorithm()).append("\",")
                    .append("\"parameter\":\"").append(r.parameter()).append("\",")
                    .append("\"operation\":\"").append(r.operation()).append("\",")
                    .append("\"dataSizeKB\":").append(r.dataSizeKB() == null ? "null" : r.dataSizeKB()).append(',')
                    .append("\"repetitions\":").append(r.repetitions()).append(',')
                    .append("\"avgMs\":").append(String.format(Locale.US, "%.6f", r.avgMs())).append(',')
                    .append("\"throughputMBs\":")
                    .append(r.throughputMBs() == null ? "null" : String.format(Locale.US, "%.6f", r.throughputMBs()))
                    .append('}');
            if (i < rows.size() - 1) {
                sb.append(',');
            }
        }
        return sb.append(']').toString();
    }
}
