package com.husovic.securevault.vault;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/vault")
@Tag(name = "Vault", description = "Otprema/preuzimanje fajlova enkriptovanih ključem sesije")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    @Operation(summary = "Otprema fajla (enkriptuje se AES-GCM ključem sesije prije čuvanja)")
    @PostMapping(value = "/{sessionId}/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public FileMetadata upload(@PathVariable String sessionId, @RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Prazan fajl");
        }
        try {
            return vaultService.upload(sessionId, file.getOriginalFilename(),
                    file.getContentType(), file.getBytes());
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Ne mogu pročitati otpremljeni fajl");
        }
    }

    @Operation(summary = "Preuzimanje i dekripcija fajla")
    @GetMapping("/{sessionId}/{fileId}/download")
    public ResponseEntity<Resource> download(@PathVariable String sessionId, @PathVariable String fileId) {
        VaultService.DecryptedFile file = vaultService.download(sessionId, fileId);
        String name = URLEncoder.encode(file.metadata().getOriginalName(), StandardCharsets.UTF_8)
                .replace("+", "%20");
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename*=UTF-8''" + name)
                .contentType(MediaType.parseMediaType(file.metadata().getContentType()))
                .contentLength(file.content().length)
                .body(new ByteArrayResource(file.content()));
    }

    @Operation(summary = "Lista fajlova u sesiji")
    @GetMapping("/{sessionId}/files")
    public List<FileMetadata> list(@PathVariable String sessionId) {
        return vaultService.list(sessionId);
    }
}
