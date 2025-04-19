// SBOMDocumentRepository.java
package com.platform.sbom.mongo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SBOMDocumentRepository extends MongoRepository<SBOMDocument, String> {
    /**
     * 查找关联指定 SBOM 元数据的完整 JSON 文档
     */
    Optional<SBOMDocument> findBySbomId(Long sbomId);

    /**
     * 删除关联指定 SBOM 元数据的完整 JSON 文档
     */
    void deleteBySbomId(Long sbomId);
}