package com.platform.sbom.controller;

import com.platform.sbom.converter.SBOMConverter;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.service.SBOMService;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.List;


@Log4j2
@RestController
@RequestMapping("/api/sbom")
public class SBOMController {

    private final SBOMService sbomService;
    private final SBOMConverter sbomConverter;

    public SBOMController(SBOMService sbomService, SBOMConverter sbomConverter) {
        this.sbomService = sbomService;
        this.sbomConverter = sbomConverter;
    }

    @GetMapping
    public ResponseEntity<List<SBOM>> getAllSBOMs() {
        return ResponseEntity.ok(sbomService.listAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<SBOM> getSBOMById(@PathVariable Long id) {
        return sbomService.find(id)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "SBOM not found with id: " + id));
    }

    /**
     * Generate SBOM for a file system (using Syft)
     */
    @PostMapping("/generate/system")
    public ResponseEntity<SBOM> generateForSystem(@RequestParam String name,
                                                  @RequestParam("systemFolder") MultipartFile[] folder,
                                                  @RequestParam(value="imageFile", required=false) MultipartFile img,
                                                  @RequestParam(value="format", required=false, defaultValue="spdx") String format) throws Exception {
        log.info("Generating SBOM for system: {} using {} format", name, format);
        SBOM sbom = sbomService.generate(name, folder, img, format);
        if (sbom == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(sbom);
    }

    /**
     * Generate SBOM for a container image (using Syft)
     */
    @PostMapping("/generate/container")
    public ResponseEntity<SBOM> generateForContainerImage(@RequestParam String name,
                                                          @RequestParam String imageName,
                                                          @RequestParam(value="format", required=false, defaultValue="spdx") String format) throws Exception {
        log.info("Generating SBOM for container image: {} using {} format", imageName, format);
        SBOM sbom = sbomService.generateForContainerImage(name, imageName, format);
        if (sbom == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(sbom);
    }

    /**
     * Download SBOM in various formats
     * - spdx: SPDX JSON
     * - cyclonedx: CycloneDX JSON
     * - custom (or blank): Custom unified format
     */
    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> downloadSBOM(@PathVariable Long id,
                                               @RequestParam(defaultValue = "custom") String format) {
        SBOM sbom = sbomService.find(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        try {
            String json;
            switch (format.toLowerCase()) {
                case "spdx":
                    json = sbomConverter.toSpdxJson(sbom);
                    break;
                case "cyclonedx":
                    json = sbomConverter.toCycloneDxJson(sbom);
                    break;
                case "custom":
                default:
                    json = sbomConverter.toCustomJson(sbom);
                    break;
            }
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setContentDisposition(ContentDisposition.attachment()
                    .filename("sbom-" + id + "-" + format + ".json")
                    .build());
            return ResponseEntity.ok().headers(headers).body(bytes);
        } catch (Exception e) {
            log.error("SBOM JSON generation failed", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "SBOM JSON generation failed", e);
        }
    }

    /**
     * Delete a specific SBOM by ID
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSBOM(@PathVariable Long id) {
        if (!sbomService.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        sbomService.delete(id);
        return ResponseEntity.noContent().build();
    }
}