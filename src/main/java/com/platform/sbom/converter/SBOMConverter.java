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
        root.put("SPDXVersion", "SPDX-2.3");
        root.put("DataLicense", "CC0-1.0");
        root.put("SPDXID", "SPDXRef-DOCUMENT-" + sbom.getSbomId());
        root.put("DocumentName", sbom.getName());
        root.put("DocumentNamespace", sbom.getNamespace());
        root.put("CreatorTool", sbom.getToolName() + "@" + sbom.getToolVersion());
        root.put("Created", sbom.getTimestamp().format(DateTimeFormatter.ISO_DATE_TIME));

        // Packages array
        ArrayNode pkgs = objectMapper.createArrayNode();
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode p = pkgs.addObject();
            // use sbomRef as SPDXID
            p.put("SPDXID", comp.getSbomRef());
            p.put("PackageName", comp.getName());
            p.put("PackageVersion", comp.getVersion());
            p.put("PackageLicenseDeclared", comp.getLicense() != null ? comp.getLicense() : "NOASSERTION");
            p.put("PackageDownloadLocation", comp.getPurl() != null ? comp.getPurl() : "NOASSERTION");
            p.put("PackageChecksum", "NOASSERTION");
            p.put("PackageSupplier", comp.getVendor() != null ? comp.getVendor() : "NOASSERTION");
            p.put("PackageVerificationCode", "");
            p.put("PackageDescription", comp.getDescription() != null ? comp.getDescription() : "");

            // 添加新的元数据
            if (comp.getFilePath() != null) {
                p.put("PackageFileName", comp.getFilePath());
            }

            if (comp.getHomePage() != null) {
                p.put("PackageHomePage", comp.getHomePage());
            }

            if (comp.getSourceRepo() != null) {
                p.put("PackageSourceInfo", comp.getSourceRepo());
            }
        }
        root.set("Packages", pkgs);

        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    public String toCycloneDxJson(SBOM sbom) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        // CycloneDX top-level
        root.put("bomFormat", "CycloneDX");
        root.put("specVersion", "1.4");
        root.put("serialNumber", "urn:uuid:" + sbom.getSbomId());
        root.put("version", sbom.getVersion());

        // metadata
        ObjectNode metadata = root.putObject("metadata");
        metadata.put("timestamp", sbom.getTimestamp().format(DateTimeFormatter.ISO_DATE_TIME));
        // tools
        ArrayNode tools = metadata.putArray("tools");
        ObjectNode tool = tools.addObject();
        tool.put("vendor", "SBOMPlatform");
        tool.put("name", sbom.getToolName());
        tool.put("version", sbom.getToolVersion());
        // source info as metadata.property
        SourceInfo src = sbom.getSource();
        if (src != null) {
            ObjectNode props = metadata.putObject("properties");
            props.put("filesystem.path", src.getFilesystem().getPath());
            props.put("filesystem.recursive", String.valueOf(src.getFilesystem().isRecursive()));
            if (src.getImage() != null) {
                props.put("image.id", src.getImage().getImageId());
                props.put("image.registry", src.getImage().getRegistry());
            }
        }

        // components
        ArrayNode comps = root.putArray("components");
        for (com.platform.sbom.model.Component comp : sbom.getComponents()) {
            ObjectNode c = comps.addObject();
            c.put("bom-ref", comp.getSbomRef());
            c.put("type", comp.getType());
            c.put("name", comp.getName());
            c.put("version", comp.getVersion());

            // 添加supplier
            if (comp.getVendor() != null) {
                c.put("supplier", comp.getVendor());
            }

            if (comp.getLicense() != null) {
                ArrayNode licArr = c.putArray("licenses");
                ObjectNode lic = licArr.addObject();
                lic.put("license", comp.getLicense());
            }

            // 添加扩展的元数据
            ArrayNode xr = c.putArray("externalReferences");

            if (comp.getPurl() != null) {
                ObjectNode ref = xr.addObject();
                ref.put("type", "purl");
                ref.put("url", comp.getPurl());
            }

            if (comp.getHomePage() != null) {
                ObjectNode ref = xr.addObject();
                ref.put("type", "website");
                ref.put("url", comp.getHomePage());
            }

            if (comp.getSourceRepo() != null) {
                ObjectNode ref = xr.addObject();
                ref.put("type", "vcs");
                ref.put("url", comp.getSourceRepo());
            }

            // 添加文件路径作为属性
            if (comp.getFilePath() != null) {
                ObjectNode props = c.putObject("properties");
                props.put("path", comp.getFilePath());
            }
        }


        // dependencies (optional)
        if (sbom.getDependencies() != null && !sbom.getDependencies().isEmpty()) {
            ArrayNode deps = root.putArray("dependencies");
            for (Dependency d : sbom.getDependencies()) {
                ObjectNode dn = deps.addObject();
                dn.put("ref", d.getRef());
                ArrayNode on = dn.putArray("dependsOn");
                d.getDependsOn().forEach(on::add);
            }
        }

        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
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
            n.put("filePath", c.getFilePath());
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

