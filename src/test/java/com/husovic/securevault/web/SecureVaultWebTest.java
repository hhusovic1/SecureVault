package com.husovic.securevault.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.husovic.securevault.crypto.asymmetric.EcdhService;
import com.husovic.securevault.crypto.kdf.HkdfService;
import com.husovic.securevault.crypto.symmetric.AesGcmService;
import com.husovic.securevault.crypto.symmetric.CipherResult;
import com.husovic.securevault.session.SessionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web-slojni testovi (MockMvc, bez pravog socketa) — provjeravaju REST rutiranje,
 * (de)serijalizaciju i multipart otpremu kroz cijeli hibridni tok preko HTTP-a.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecureVaultWebTest {

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired EcdhService ecdh;
    @Autowired HkdfService hkdf;
    @Autowired AesGcmService aes;

    @Test
    void serverIdentityEndpointReturnsCertificate() throws Exception {
        mvc.perform(get("/api/handshake/server-identity"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("SecureVault Server"))
                .andExpect(jsonPath("$.signatureBase64").isNotEmpty());
    }

    @Test
    void fullFlowOverHttp() throws Exception {
        String curve = EcdhService.CURVE_25519;
        KeyPair client = ecdh.generateKeyPair(curve);
        String clientPub = ecdh.encodePublicKey(client.getPublic());

        // --- init ---
        String initBody = json.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("curve", curve);
            put("clientEcdhPublicKey", clientPub);
        }});
        MvcResult initRes = mvc.perform(post("/api/handshake/init")
                        .contentType(MediaType.APPLICATION_JSON).content(initBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessionId").isNotEmpty())
                .andReturn();
        JsonNode init = json.readTree(initRes.getResponse().getContentAsString());
        String sessionId = init.get("sessionId").asText();

        // --- klijent izvede ključ i pošalje Finished ---
        PublicKey serverPub = ecdh.decodePublicKey(curve, init.get("serverEcdhPublicKey").asText());
        byte[] shared = ecdh.computeSharedSecret(curve, client.getPrivate(), serverPub);
        byte[] key = hkdf.deriveAes256Key(shared, null, init.get("hkdfInfo").asText());
        CipherResult conf = aes.encrypt(SessionService.expectedFinished(sessionId)
                .getBytes(StandardCharsets.UTF_8), aes.keyFromBytes(key));

        String finishBody = json.writeValueAsString(new java.util.LinkedHashMap<>() {{
            put("sessionId", sessionId);
            put("confirmationIv", conf.ivBase64());
            put("confirmationCiphertext", conf.ciphertextBase64());
        }});
        mvc.perform(post("/api/handshake/finish")
                        .contentType(MediaType.APPLICATION_JSON).content(finishBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ESTABLISHED"));

        // --- vault upload (multipart) ---
        byte[] content = "Sadržaj preko HTTP-a".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile file = new MockMultipartFile("file", "nota.txt", "text/plain", content);
        MvcResult upRes = mvc.perform(multipart("/api/vault/" + sessionId + "/upload").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fileId").isNotEmpty())
                .andReturn();
        String fileId = json.readTree(upRes.getResponse().getContentAsString()).get("fileId").asText();

        // --- vault download i provjera round-trip-a ---
        MvcResult dlRes = mvc.perform(get("/api/vault/" + sessionId + "/" + fileId + "/download"))
                .andExpect(status().isOk())
                .andReturn();
        assertArrayEquals(content, dlRes.getResponse().getContentAsByteArray());
    }

    @Test
    void symmetricBenchmarkEndpoint() throws Exception {
        MvcResult res = mvc.perform(get("/api/benchmark/symmetric")
                        .param("algorithm", "AES").param("keySize", "256")
                        .param("dataSizeKB", "32").param("repetitions", "3").param("warmup", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("AES"))
                .andReturn();
        double throughput = json.readTree(res.getResponse().getContentAsString())
                .get("encryptThroughputMBs").asDouble();
        assertTrue(throughput > 0, "propusnost mora biti pozitivna");
    }
}
