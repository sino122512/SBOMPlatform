package com.platform.sbom.mongo;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "sbomDocuments")
public class SBOMDocument {
    @Id
    private String id;
    // 与 MySQL 中 SBOM 的 id 关联
    private Long sbomId;
    // 完整 SBOM JSON 字符串
    private String jsonContent;

    public SBOMDocument() {}

    public SBOMDocument(Long sbomId, String jsonContent) {
        this.sbomId = sbomId;
        this.jsonContent = jsonContent;
    }

    // getters and setters...
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public Long getSbomId() { return sbomId; }
    public void setSbomId(Long sbomId) { this.sbomId = sbomId; }
    public String getJsonContent() { return jsonContent; }
    public void setJsonContent(String jsonContent) { this.jsonContent = jsonContent; }
}