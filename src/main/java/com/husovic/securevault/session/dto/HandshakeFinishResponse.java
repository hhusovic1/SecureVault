package com.husovic.securevault.session.dto;

public record HandshakeFinishResponse(String sessionId, String status, String message) {
}
