package com.husovic.securevault.vault;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FileMetadataRepository extends JpaRepository<FileMetadata, String> {
    List<FileMetadata> findBySessionId(String sessionId);
}
