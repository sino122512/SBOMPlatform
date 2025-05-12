package com.platform.sbom.converter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.platform.sbom.model.Dependency;
import com.platform.sbom.model.FileSystemInfo;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.model.SourceInfo;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeFormatter;

@Component
public class SBOMConverter {
    private final ObjectMapper objectMapper;

    public SBOMConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public String toSpdxJson(SBOM sbom) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        // SPDX document metadata
        root.put("SPDXVersion", sbom.getSpecVersion() != null && sbom.getSpecVersion().startsWith("SPDX") ?
                sbom.getSpecVersion() : "SPDX-2.3");
        root.put("DataLicense", "CC0-1.0");
        root.put("SPDXID", "SPDXRef-DOCUMENT");
        root.put("name", sbom.getName());
        root.put("documentNamespace", sbom.getNamespace());
        
        // 创建者信息
        ArrayNode creators = objectMapper.createArrayNode();
        creators.add("Tool: " + sbom.getToolName() + "-" + sbom.getToolVersion());
        root.set("creator", creators);
        
        root.put("created", sbom.getTimestamp().format(DateTimeFormatter.ISO_DATE_TIME));

        // Packages array
        ArrayNode packagesArray = objectMapper.createArrayNode();
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode pkg = packagesArray.addObject();
            // 使用SPDXRef-前缀的sbomRef作为SPDXID
            String spdxId = comp.getSbomRef();
            if (!spdxId.startsWith("SPDXRef-")) {
                spdxId = "SPDXRef-" + spdxId;
            }
            pkg.put("SPDXID", spdxId);
            pkg.put("name", comp.getName());
            pkg.put("versionInfo", comp.getVersion());
            pkg.put("licenseConcluded", comp.getLicense() != null ? comp.getLicense() : "NOASSERTION");
            pkg.put("licenseDeclared", comp.getLicense() != null ? comp.getLicense() : "NOASSERTION");
            pkg.put("downloadLocation", comp.getPurl() != null ? comp.getPurl() : "NOASSERTION");
            pkg.put("filesAnalyzed", false);
            pkg.put("supplier", comp.getVendor() != null ? "Organization: " + comp.getVendor() : "NOASSERTION");
            pkg.put("description", comp.getDescription() != null ? comp.getDescription() : "");
            
            // 添加primaryPackagePurpose
            pkg.put("primaryPackagePurpose", comp.getType());

            // 添加外部引用
            ArrayNode externalRefs = objectMapper.createArrayNode();
            if (comp.getPurl() != null) {
                ObjectNode purlRef = externalRefs.addObject();
                purlRef.put("referenceCategory", "PACKAGE-MANAGER");
                purlRef.put("referenceType", "purl");
                purlRef.put("referenceLocator", comp.getPurl());
            }
            
            if (comp.getCpe() != null) {
                ObjectNode cpeRef = externalRefs.addObject();
                cpeRef.put("referenceCategory", "SECURITY");
                cpeRef.put("referenceType", "cpe23Type");
                cpeRef.put("referenceLocator", comp.getCpe());
            }
            
            if (externalRefs.size() > 0) {
                pkg.set("externalRefs", externalRefs);
            }

        
        }
        root.set("packages", packagesArray);

        // 添加依赖关系
        ArrayNode relationships = objectMapper.createArrayNode();
        for (Dependency dep : sbom.getDependencies()) {
            String sourceId = dep.getRef();
            if (!sourceId.startsWith("SPDXRef-")) {
                sourceId = "SPDXRef-" + sourceId;
            }
            
            for (String targetId : dep.getDependsOn()) {
                ObjectNode rel = relationships.addObject();
                rel.put("spdxElementId", sourceId);
                rel.put("relationshipType", "DEPENDS_ON");
                if (!targetId.startsWith("SPDXRef-")) {
                    targetId = "SPDXRef-" + targetId;
                }
                rel.put("relatedSpdxElement", targetId);
            }
        }
        root.set("relationships", relationships);

        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    public String toCycloneDxJson(SBOM sbom) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        // CycloneDX top-level 规范版本
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", sbom.getSpecVersion() != null && sbom.getSpecVersion().startsWith("CycloneDX") ?
                sbom.getSpecVersion().substring("CycloneDX-".length()) : "1.4");
        root.put("serialNumber", "urn:uuid:" + sbom.getSbomId());
        root.put("version", sbom.getVersion());

        // metadata
        ObjectNode metadata = root.putObject("metadata");
        metadata.put("timestamp", sbom.getTimestamp().format(DateTimeFormatter.ISO_DATE_TIME));
        
        // 添加元数据组件
        ObjectNode component = metadata.putObject("component");
        component.put("type", "application");
        component.put("name", sbom.getName());
        component.put("bom-ref", "bom-ref-" + sbom.getSbomId());
        
        // tools
        ArrayNode tools = metadata.putArray("tools");
        ObjectNode tool = tools.addObject();
        tool.put("vendor", "SBOMPlatform");
        tool.put("name", sbom.getToolName());
        tool.put("version", sbom.getToolVersion());
        
        // source info as metadata.property
        SourceInfo src = sbom.getSource();
        if (src != null) {
            ArrayNode properties = metadata.putArray("properties");
            if (src.getFilesystem() != null) {
                addProperty(properties, "filesystem.path", src.getFilesystem().getPath());
                addProperty(properties, "filesystem.recursive", String.valueOf(src.getFilesystem().isRecursive()));
            }
            if (src.getImage() != null) {
                addProperty(properties, "image.id", src.getImage().getImageId());
                addProperty(properties, "image.registry", src.getImage().getRegistry());
            }
        }

        // components
        ArrayNode comps = root.putArray("components");
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode c = comps.addObject();
            c.put("bom-ref", comp.getSbomRef());
            
            // 设置组件类型，根据CycloneDX规范
            String type = mapTypeToCycloneDX(comp.getType());
            c.put("type", type);
            
            c.put("name", comp.getName());
            c.put("version", comp.getVersion());

            // 添加发布商
            if (comp.getVendor() != null) {
                c.put("publisher", comp.getVendor());
            }
            
            // 添加描述
            if (comp.getDescription() != null) {
                c.put("description", comp.getDescription());
            }

            // 添加许可证信息
            if (comp.getLicense() != null) {
                ArrayNode licArr = c.putArray("licenses");
                ObjectNode lic = licArr.addObject();
                // 区分SPDX许可证ID和表达式
                if (comp.getLicense().contains(" ") || 
                    comp.getLicense().contains("(") || 
                    comp.getLicense().contains(")")) {
                    lic.put("expression", comp.getLicense());
                } else {
                    ObjectNode licData = lic.putObject("license");
                    licData.put("id", comp.getLicense());
                }
            }

            // 添加PURL和CPE
            if (comp.getPurl() != null) {
                c.put("purl", comp.getPurl());
            }
            
            if (comp.getCpe() != null) {
                c.put("cpe", comp.getCpe());
            }

            // 添加扩展的外部引用
            ArrayNode externalRefs = c.putArray("externalReferences");

            if (comp.getHomePage() != null) {
                ObjectNode ref = externalRefs.addObject();
                ref.put("type", "website");
                ref.put("url", comp.getHomePage());
            }

            if (comp.getSourceRepo() != null) {
                ObjectNode ref = externalRefs.addObject();
                ref.put("type", "vcs");
                ref.put("url", comp.getSourceRepo());
            }
        }

        // dependencies (optional)
        if (sbom.getDependencies() != null && !sbom.getDependencies().isEmpty()) {
            ArrayNode deps = root.putArray("dependencies");
            for (Dependency d : sbom.getDependencies()) {
                ObjectNode dn = deps.addObject();
                dn.put("ref", d.getRef());
                if (d.getDependsOn() != null && !d.getDependsOn().isEmpty()) {
                    ArrayNode on = dn.putArray("dependsOn");
                    d.getDependsOn().forEach(on::add);
                }
            }
        }

        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }
    
    // 辅助方法：添加CycloneDX格式的属性
    private void addProperty(ArrayNode properties, String name, String value) {
        if (value != null) {
            ObjectNode property = properties.addObject();
            property.put("name", name);
            property.put("value", value);
        }
    }
    
    // 辅助方法：将组件类型映射到CycloneDX规定的类型
    private String mapTypeToCycloneDX(String type) {
        if (type == null) return "library";
        
        switch (type.toLowerCase()) {
            case "application":
            case "app":
                return "application";
            case "framework":
                return "framework";
            case "library":
            case "lib":
                return "library";
            case "container":
                return "container";
            case "platform":
                return "platform";
            case "operating-system":
            case "os":
                return "operating-system";
            case "device":
                return "device";
            case "firmware":
                return "firmware";
            case "file":
                return "file";
            default:
                return "library"; // 默认为library
        }
    }

    public String toCustomJson(SBOM s) throws Exception {
        ObjectNode r = objectMapper.createObjectNode();
        // sbom
        ObjectNode m = r.putObject("sbom");
        m.put("id", s.getSbomId());
        m.put("version", s.getVersion());
        m.put("name", s.getName());
        m.put("timestamp", s.getTimestamp().toString());
        m.put("namespace", s.getNamespace());
        ObjectNode t = m.putObject("tool");
        t.put("name", s.getToolName());
        t.put("version", s.getToolVersion());
        // components
        ArrayNode ca = r.putArray("components");
        s.getComponents().forEach(c -> {
            ObjectNode n = ca.addObject();
            n.put("id", c.getSbomRef());
            n.put("name", c.getName());
            n.put("version", c.getVersion());
            n.put("type", c.getType());
            n.put("license", c.getLicense());
            n.put("purl", c.getPurl());
            n.put("cpe", c.getCpe());
            n.put("description", c.getDescription());

            // 添加扩展元数据
            n.put("sourceRepo", c.getSourceRepo());
            n.put("vendor", c.getVendor());
            n.put("homePage", c.getHomePage());
        });
        // dependencies
        ArrayNode da = r.putArray("dependencies");
        s.getDependencies().forEach(d -> {
            ObjectNode n = da.addObject();
            n.put("ref", d.getRef());
            ArrayNode d2 = n.putArray("dependsOn");
            d.getDependsOn().forEach(d2::add);
        });
        // source
        ObjectNode sn = r.putObject("source");
        SourceInfo src = s.getSource();

        ObjectNode fsn = sn.putObject("filesystem");

        if (src != null && src.getFilesystem() != null) {
            FileSystemInfo fs = src.getFilesystem();
            fsn.put("path", fs.getPath());
            fsn.put("recursive", fs.isRecursive());
            if (src.getImage() != null) {
                ObjectNode in = sn.putObject("image");
                in.put("imageId", src.getImage().getImageId());
                in.put("registry", src.getImage().getRegistry());
            }
        }else {
                // Default values if source info is missing
                fsn.put("path", "unknown");
                fsn.put("recursive", false);
        }
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(r);
    }
}

