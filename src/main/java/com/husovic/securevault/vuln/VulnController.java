package com.husovic.securevault.vuln;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Edukativne demonstracije slabosti algoritama. Sve je izolovano u {@code vuln}
 * paketu i radi isključivo nad podacima/ključevima koje aplikacija sama generiše.
 */
@RestController
@RequestMapping("/api/vuln")
@Tag(name = "Vulnerability (edukativno)", description = "Kontrolisane demonstracije slabosti — Faza 4")
public class VulnController {

    private final DesBruteForceService bruteForceService;

    public VulnController(DesBruteForceService bruteForceService) {
        this.bruteForceService = bruteForceService;
    }

    @Operation(summary = "Brute-force na skraćenom DES ključu",
            description = "Isprobava svih 2^keyBits ključeva nad poznatim parom (tekst, šifrat) i mjeri vrijeme. "
                    + "Pokazuje eksponencijalni rast troška napada.")
    @GetMapping("/des-bruteforce")
    public DesBruteForceService.BruteForceResult bruteForce(@RequestParam(defaultValue = "20") int keyBits) {
        return bruteForceService.run(keyBits);
    }

    @Operation(summary = "Skaliranje brute-force napada po dužini ključa",
            description = "Vraća niz tačaka (vrijeme vs. broj bitova) za crtanje eksponencijalne krive.")
    @GetMapping("/des-bruteforce/scaling")
    public List<DesBruteForceService.BruteForceResult> scaling(
            @RequestParam(defaultValue = "8") int minBits,
            @RequestParam(defaultValue = "24") int maxBits) {
        return bruteForceService.scaling(minBits, maxBits);
    }
}
