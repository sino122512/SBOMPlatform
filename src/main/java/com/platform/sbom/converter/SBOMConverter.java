package com.platform.sbom.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.platform.sbom.model.SBOM;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Component
public class SBOMConverter {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String toSpdxJson(SBOM sbom) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("SPDXVersion", "SPDX-2.3");
        root.put("dataLicense", "CC0-1.0");
        root.put("SPDXID", "SPDXRef-DOCUMENT");
        root.put("documentName", sbom.getName());
        root.put("documentNamespace", "https://example.com/spdx/" + UUID.randomUUID().toString());
        root.put("created", sbom.getGeneratedAt().format(DateTimeFormatter.ISO_DATE_TIME));

        ArrayNode packagesArray = objectMapper.createArrayNode();
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode compNode = objectMapper.createObjectNode();
            compNode.put("SPDXID", "SPDXRef-Package-" + comp.getName());
            compNode.put("packageName", comp.getName());
            compNode.put("packageVersion", comp.getVersion());
            compNode.put("packageLicenseDeclared", comp.getLicense() != null ? comp.getLicense() : "NOASSERTION");
            compNode.put("packageDescription", comp.getDescription() != null ? comp.getDescription() : "");
            packagesArray.add(compNode);
        }
        root.set("packages", packagesArray);
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    public String toCycloneDxJson(SBOM sbom) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.4");
        root.put("serialNumber", "urn:uuid:" + UUID.randomUUID().toString());
        root.put("version", 1);

        ObjectNode metadata = objectMapper.createObjectNode();
        metadata.put("timestamp", sbom.getGeneratedAt().format(DateTimeFormatter.ISO_DATE_TIME));
        ArrayNode tools = objectMapper.createArrayNode();
        ObjectNode tool = objectMapper.createObjectNode();
        tool.put("vendor", "SBOMPlatform");
        tool.put("name", "SBOM Generator");
        tool.put("version", "1.0.0");
        tools.add(tool);
        metadata.set("tools", tools);
        root.set("metadata", metadata);

        ArrayNode componentsArray = objectMapper.createArrayNode();
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode compNode = objectMapper.createObjectNode();
            compNode.put("bom-ref", "pkg:" + comp.getName() + "@" + comp.getVersion());
            compNode.put("type", comp.getType());
            compNode.put("name", comp.getName());
            compNode.put("version", comp.getVersion());
            if (comp.getLicense() != null) {
                ObjectNode licenseNode = objectMapper.createObjectNode();
                licenseNode.put("id", comp.getLicense());
                ArrayNode licenseArray = objectMapper.createArrayNode();
                licenseArray.add(licenseNode);
                compNode.set("licenses", licenseArray);
            }
            componentsArray.add(compNode);
        }
        root.set("components", componentsArray);
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    public String toCustomJson(SBOM sbom) throws Exception {
        // 直接序列化 SBOM 对象为 JSON
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(sbom);
    }
}