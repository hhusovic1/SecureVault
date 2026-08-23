package com.husovic.securevault.session;

import com.husovic.securevault.crypto.signature.SimpleCertificate;
import com.husovic.securevault.session.dto.HandshakeFinishRequest;
import com.husovic.securevault.session.dto.HandshakeFinishResponse;
import com.husovic.securevault.session.dto.HandshakeInitRequest;
import com.husovic.securevault.session.dto.HandshakeInitResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/handshake")
@Tag(name = "Handshake", description = "Uspostava sigurne sesije (ECDH + potpis + HKDF)")
public class HandshakeController {

    private final SessionService sessionService;
    private final ServerIdentityService serverIdentity;

    public HandshakeController(SessionService sessionService, ServerIdentityService serverIdentity) {
        this.sessionService = sessionService;
        this.serverIdentity = serverIdentity;
    }

    @Operation(summary = "Certifikat i identitetski javni ključ servera",
            description = "Klijent unaprijed dohvata i \"pinuje\" ovaj ključ da bi mogao verifikovati potpis pri init-u.")
    @GetMapping("/server-identity")
    public SimpleCertificate serverIdentity() {
        return serverIdentity.certificate();
    }

    @Operation(summary = "Korak 1 — inicijalizacija handshake-a",
            description = "Klijent šalje efemerni ECDH javni ključ; server vraća svoj efemerni ključ, "
                    + "potpis transkripta i certifikat.")
    @PostMapping("/init")
    public HandshakeInitResponse init(@Valid @RequestBody HandshakeInitRequest request) {
        return sessionService.init(request);
    }

    @Operation(summary = "Korak 2 — završetak handshake-a",
            description = "Klijent šalje AES-GCM \"Finished\" poruku; server je verifikuje i uspostavi sesiju.")
    @PostMapping("/finish")
    public HandshakeFinishResponse finish(@Valid @RequestBody HandshakeFinishRequest request) {
        return sessionService.finish(request);
    }
}
