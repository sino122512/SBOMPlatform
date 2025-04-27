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
    /**
     * SBOMController 构造函数
     *
     * @param sbomService SBOM 服务
     * @param sbomConverter SBOM 转换器
     */
    public SBOMController(SBOMService sbomService, SBOMConverter sbomConverter) {
        this.sbomService = sbomService;
        this.sbomConverter = sbomConverter;
    }



    @GetMapping
    public ResponseEntity<List<SBOM>> getAllSBOMs() {
        return ResponseEntity.ok(sbomService.listAll());
    }

    /**
     * 根据 ID 获取 SBOM 详情
     */
    @GetMapping("/{id}")
    public ResponseEntity<SBOM> getSBOMById(@PathVariable Long id) {
        return sbomService.find(id)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "SBOM not found with id: " + id));
    }

    @PostMapping("/generate/system")
    public ResponseEntity<SBOM> generateForSystem(@RequestParam String name,
                                                  @RequestParam("systemFolder") MultipartFile[] folder,
                                                  @RequestParam(value="imageFile", required=false) MultipartFile img) throws Exception {
        SBOM sbom = sbomService.generate(name, folder, img);
        if (sbom == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(sbom);
    }


    /**
     * 下载 SBOM JSON 文件，支持 format 参数：
     * - spdx ：SPDX JSON
     * - cyclonedx ：CycloneDX JSON
     * - custom（或 blank）: 自定义统一格式
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
            log.error("SBOM JSON 生成失败", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "SBOM JSON 生成失败", e);
        }
    }

    /**
     * 删除指定 id 的 SBOM
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