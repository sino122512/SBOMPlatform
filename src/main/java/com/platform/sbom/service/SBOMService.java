package com.platform.sbom.service;

import com.platform.sbom.converter.SBOMConverter;
import com.platform.sbom.mongo.SBOMDocument;
import com.platform.sbom.mongo.SBOMDocumentRepository;
import com.platform.sbom.model.*;
import com.platform.sbom.repository.SBOMRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.nio.file.Files;
import java.util.*;

@Service
public class SBOMService {
    private final SBOMRepository repo;
    private final SBOMDocumentRepository docRepo;
    private final ScannerService scanner;
    private final SBOMConverter converter;

    public SBOMService(SBOMRepository repo, SBOMDocumentRepository docRepo,
                       ScannerService scanner, SBOMConverter converter) {
        this.repo = repo; this.docRepo = docRepo;
        this.scanner = scanner; this.converter = converter;
    }
    public boolean existsById(Long id){
        return repo.existsById(id);
    }
    public List<SBOM> listAll() { return repo.findAll(); }
    public Optional<SBOM> find(Long id) { return repo.findById(id); }

    @Transactional
    public SBOM generate(String name, MultipartFile[] folder, MultipartFile img) throws Exception {
        // 保存并扫描文件夹
        File tmpF = Files.createTempDirectory("sys").toFile();
        for (MultipartFile mf: folder) {
            File dest = new File(tmpF, mf.getOriginalFilename());
            dest.getParentFile().mkdirs();
            mf.transferTo(dest);
        }
        List<Component> comps = scanner.scanFileSystem(tmpF.getAbsolutePath());
        // 可扩展依赖构建
        List<Dependency> deps = Collections.emptyList();

        // 若含镜像文件
        if (img!=null && !img.isEmpty()) {
            File tmpI = File.createTempFile("img", ".tar");
            img.transferTo(tmpI);
            comps.addAll(scanner.scanContainerImageFromFile(tmpI));
            tmpI.delete();
        }
        // 构建 SBOM 对象
        SBOM sb = new SBOM();
        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        sb.setToolName("SBOMPlatform");
        sb.setToolVersion("1.0.0");
        sb.setComponents(comps);
        sb.setDependencies(deps);
        // 保存 DB
        SBOM saved = repo.save(sb);
        // 存 Mongo JSON
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));
        return saved;
    }

    @Transactional
    public void delete(Long id) {
        docRepo.deleteBySbomId(id);
        repo.deleteById(id);
    }
}
