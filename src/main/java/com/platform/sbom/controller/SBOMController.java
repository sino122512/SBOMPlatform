package com.platform.sbom.controller;

import com.platform.sbom.converter.SBOMConverter;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.service.SBOMService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/sbom")
public class SBOMController {

    private final SBOMService sbomService;
    private final SBOMConverter sbomConverter;

    public SBOMController(SBOMService sbomService, SBOMConverter sbomConverter) {
        this.sbomService = sbomService;
        this.sbomConverter = sbomConverter;
    }

    @PostMapping("/generate/dir")
    public ResponseEntity<SBOM> generateFromDirectory(@RequestParam String name,
                                                      @RequestParam(defaultValue = "cyclonedx-json") String format,
                                                      @RequestParam String path) {
        SBOM sbom = sbomService.generateSBOMFromDirectory(name, format, path);
        return ResponseEntity.ok(sbom);
    }

    @PostMapping("/generate/image")
    public ResponseEntity<SBOM> generateFromImage(@RequestParam String imageName,
                                                  @RequestParam String name,
                                                  @RequestParam(defaultValue = "cyclonedx-json") String format) {
        SBOM sbom = sbomService.generateSBOMFromImage(imageName, name, format);
        return ResponseEntity.ok(sbom);
    }

    @GetMapping
    public ResponseEntity<List<SBOM>> getAllSBOMs() {
        return ResponseEntity.ok(sbomService.getAllSBOMs());
    }

    @GetMapping("/{id}")
    public ResponseEntity<SBOM> getSBOMById(@PathVariable Long id) {
        SBOM sbom = sbomService.getSBOMById(id);
        if (sbom == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(sbom);
    }

    /**
     * 下载指定 SBOM 的 JSON 文件，支持 format 参数：spdx, cyclonedx, custom
     */
    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> downloadSBOM(@PathVariable Long id,
                                               @RequestParam(defaultValue = "custom") String format) {
        SBOM sbom = sbomService.getSBOMById(id);
        if (sbom == null) {
            return ResponseEntity.notFound().build();
        }
        try {
            String jsonOutput;
            switch (format.toLowerCase()) {
                case "spdx":
                    jsonOutput = sbomConverter.toSpdxJson(sbom);
                    break;
                case "cyclonedx":
                    jsonOutput = sbomConverter.toCycloneDxJson(sbom);
                    break;
                case "custom":
                default:
                    jsonOutput = sbomConverter.toCustomJson(sbom);
                    break;
            }
            byte[] fileContent = jsonOutput.getBytes(StandardCharsets.UTF_8);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setContentDispositionFormData("attachment", "sbom-" + id + "-" + format + ".json");
            return ResponseEntity.ok().headers(headers).body(fileContent);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
}