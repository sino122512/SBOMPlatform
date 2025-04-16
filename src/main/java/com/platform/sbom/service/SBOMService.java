package com.platform.sbom.service;

import com.platform.sbom.model.Component;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.repository.SBOMRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SBOMService {
    private final SBOMRepository sbomRepository;
    private final ScannerService scannerService;

    public SBOMService(SBOMRepository sbomRepository, ScannerService scannerService) {
        this.sbomRepository = sbomRepository;
        this.scannerService = scannerService;
    }

    /**
     * 模拟扫描目录并生成 SBOM 数据。
     * 实际中可调用文件扫描、容器镜像解析等逻辑
     */
    public SBOM generateSBOM(String name, String format) {
        SBOM sbom = new SBOM();
        sbom.setName(name);
        sbom.setFormat(format);

        // 模拟生成组件数据,用于测试
        List<Component> components = new ArrayList<>();
        components.add(createComponent("spring-boot", "3.0.5", "library", "Apache-2.0", "Spring Boot 核心库"));
        components.add(createComponent("hibernate-core", "6.2.0.Final", "library", "LGPL", "Hibernate ORM"));
        components.add(createComponent("jackson-databind", "2.14.1", "library", "Apache-2.0", "JSON 解析库"));
        // 可添加更多组件……

        sbom.setComponents(components);
        // 保存到数据库
        return sbomRepository.save(sbom);
    }

    private Component createComponent(String name, String version, String type, String license, String description) {
        Component comp = new Component();
        comp.setName(name);
        comp.setVersion(version);
        comp.setType(type);
        comp.setLicense(license);
        comp.setDescription(description);
        return comp;
    }

    public List<SBOM> getAllSBOMs() {
        return sbomRepository.findAll();
    }

    public SBOM getSBOMById(Long id) {
        return sbomRepository.findById(id).orElse(null);
    }

    /**
     * 根据文件系统目录生成 SBOM（调用扫描模块）
     */
    public SBOM generateSBOMFromDirectory(String name, String format, String dirPath) {
        List<Component> components = scannerService.scanFileSystem(dirPath);
        SBOM sbom = new SBOM();
        sbom.setName(name);
        sbom.setFormat(format);
        sbom.setComponents(components);
        return sbomRepository.save(sbom);
    }

    /**
     * 根据容器镜像生成 SBOM（调用扫描模块）
     */
    public SBOM generateSBOMFromImage(String imageName, String name, String format) {
        List<Component> components = scannerService.scanContainerImage(imageName);
        SBOM sbom = new SBOM();
        sbom.setName(name);
        sbom.setFormat(format);
        sbom.setComponents(components);
        return sbomRepository.save(sbom);
    }
}