package com.platform.sbom.service;

import com.platform.sbom.converter.SBOMConverter;
import com.platform.sbom.model.*;
import com.platform.sbom.mongo.SBOMDocument;
import com.platform.sbom.mongo.SBOMDocumentRepository;
import com.platform.sbom.repository.SBOMRepository;
import org.springframework.jdbc.core.JdbcTemplate;
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
    private final JdbcTemplate jdbcTemplate;
    private final MavenPomParserService mavenPomParser;


    public SBOMService(SBOMRepository repo, SBOMDocumentRepository docRepo,
                       ScannerService scanner, SBOMConverter converter, JdbcTemplate jdbcTemplate, MavenPomParserService mavenPomParser) {
        this.repo = repo; this.docRepo = docRepo;
        this.scanner = scanner; this.converter = converter;
        this.jdbcTemplate = jdbcTemplate;
        this.mavenPomParser = mavenPomParser;
    }
    public boolean existsById(Long id){
        return repo.existsById(id);
    }
    public List<SBOM> listAll() { return repo.findAll(); }
    public Optional<SBOM> find(Long id) { return repo.findById(id); }

    /**
     * 从Maven项目生成SBOM
     */
    @Transactional
    public SBOM generateFromMavenProject(String name, MultipartFile[] projectFiles, MultipartFile img) throws Exception {
        // 保存上传的Maven项目文件到临时目录
        File tmpDir = Files.createTempDirectory("maven_project").toFile();
        Map<String, String> originalPaths = new HashMap<>();

        // 保存所有上传文件
        for (MultipartFile file : projectFiles) {
            String originalName = file.getOriginalFilename();
            if (originalName != null) {
                // 确保路径存在
                String relativePath = originalName;
                File destFile = new File(tmpDir, relativePath);
                destFile.getParentFile().mkdirs();
                file.transferTo(destFile);

                // 记录路径映射
                originalPaths.put(destFile.getAbsolutePath(), originalName);
            }
        }

        // 收集所有组件
        List<Component> components = new ArrayList<>();

        // 1. 扫描并解析所有pom.xml文件
        List<File> pomFiles = mavenPomParser.findPomFiles(tmpDir.getAbsolutePath());
        for (File pomFile : pomFiles) {
            List<Component> pomComponents = mavenPomParser.parsePomFile(pomFile);
            components.addAll(pomComponents);
        }

        // 2. 同时也扫描JAR文件
        List<Component> jarComponents = scanner.scanFileSystem(tmpDir.getAbsolutePath());

        // 合并组件列表，避免重复
        Map<String, Component> uniqueComponents = new HashMap<>();

        // 先添加pom.xml中的依赖，它们的数据通常更完整
        for (Component comp : components) {
            uniqueComponents.put(comp.getSbomRef(), comp);
        }

        // 再添加JAR扫描的结果，但不覆盖已有的
        for (Component comp : jarComponents) {
            if (!uniqueComponents.containsKey(comp.getSbomRef())) {
                uniqueComponents.put(comp.getSbomRef(), comp);
            }
        }

        // 将临时文件路径替换为原始上传文件路径
        for (Component comp : uniqueComponents.values()) {
            String tempPath = comp.getFilePath();
            if (tempPath != null) {
                for (String key : originalPaths.keySet()) {
                    if (tempPath.startsWith(key)) {
                        comp.setFilePath(originalPaths.get(key));
                        break;
                    } else if (tempPath.contains(key)) {
                        comp.setFilePath(tempPath.replace(key, originalPaths.get(key)));
                        break;
                    }
                }
            }
        }

        // 使用当前已有的增强逻辑
        List<Component> finalComponents = new ArrayList<>(uniqueComponents.values());
        enhanceLicenseInfo(finalComponents);
        enrichMavenMetadata(finalComponents);

        // 构建依赖关系
        List<Dependency> deps = buildDependencies(finalComponents);

        // 创建源信息
        SourceInfo sourceInfo = new SourceInfo();
        FileSystemInfo fsInfo = new FileSystemInfo(tmpDir.getAbsolutePath(), true);
        sourceInfo.setFilesystem(fsInfo);

        // 若含镜像文件
        if (img != null && !img.isEmpty()) {
            File tmpI = File.createTempFile("img", ".tar");
            img.transferTo(tmpI);
            List<Component> imageComps = scanner.scanContainerImageFromFile(tmpI);

            // 为镜像中的组件设置源信息
            for (Component comp : imageComps) {
                comp.setSourceRepo("container-image");
                if (comp.getDescription() == null) {
                    comp.setDescription("From container image");
                }
            }

            finalComponents.addAll(imageComps);
            tmpI.delete();

            // 更新源信息
            ImageInfo imgInfo = new ImageInfo(
                    img.getOriginalFilename(),
                    "local-upload"
            );
            sourceInfo.setImage(imgInfo);
        }

        // 构建SBOM对象
        SBOM sb = new SBOM();
        // 手动分配ID
        Long maxId = jdbcTemplate.queryForObject(
                "SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);

        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        sb.setToolName("SBOMPlatform");
        sb.setToolVersion("1.0.0");
        sb.setComponents(finalComponents);
        sb.setDependencies(deps);
        sb.setSource(sourceInfo);

        // 保存到数据库
        SBOM saved = repo.save(sb);
        // 存MongoDB JSON
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));

        return saved;
    }

    @Transactional
    public SBOM generate(String name, MultipartFile[] folder, MultipartFile img) throws Exception {
        // 保存并扫描文件夹
        File tmpF = Files.createTempDirectory("sys").toFile();
        // 创建一个映射表来存储原始文件路径
        Map<String, String> originalPaths = new HashMap<>();

        for (MultipartFile mf: folder) {
            String originalName = mf.getOriginalFilename();
            File dest = new File(tmpF, originalName);
            dest.getParentFile().mkdirs();
            mf.transferTo(dest);

            // 记录原始路径
            if (originalName != null) {
                originalPaths.put(dest.getAbsolutePath(), originalName);
            }
        }

        List<Component> comps = scanner.scanFileSystem(tmpF.getAbsolutePath());

        // 将临时文件路径替换为原始上传文件路径
        for (Component comp : comps) {
            String tempPath = comp.getFilePath();
            if (tempPath != null) {
                for (String key : originalPaths.keySet()) {
                    if (tempPath.startsWith(key)) {
                        // 替换为原始路径
                        comp.setFilePath(originalPaths.get(key));
                        break;
                    } else if (tempPath.contains(key)) {
                        // 部分匹配，替换那部分
                        comp.setFilePath(tempPath.replace(key, originalPaths.get(key)));
                        break;
                    }
                }
            }
        }

        // 使用LicenseDetector增强许可证信息
        enhanceLicenseInfo(comps);

        // 使用MavenMetadataEnricher增强Maven元数据
        enrichMavenMetadata(comps);

        // 可扩展依赖构建
        List<Dependency> deps = buildDependencies(comps);

        // Create source info
        SourceInfo sourceInfo = new SourceInfo();
        FileSystemInfo fsInfo = new FileSystemInfo(tmpF.getAbsolutePath(), true);
        sourceInfo.setFilesystem(fsInfo);

        // 若含镜像文件
        if (img!=null && !img.isEmpty()) {
            File tmpI = File.createTempFile("img", ".tar");
            img.transferTo(tmpI);
            List<Component> imageComps = scanner.scanContainerImageFromFile(tmpI);

            // 为镜像中的组件设置源信息
            for (Component comp : imageComps) {
                comp.setSourceRepo("container-image");
                if (comp.getDescription() == null) {
                    comp.setDescription("From container image");
                }
            }

            comps.addAll(imageComps);
            tmpI.delete();

            // 更新源信息
            ImageInfo imgInfo = new ImageInfo(
                    img.getOriginalFilename(),
                    "local-upload"
            );
            sourceInfo.setImage(imgInfo);
        }

        // 构建 SBOM 对象
        SBOM sb = new SBOM();
        // 手动分配 ID：查询当前最大 ID 并 +1
        Long maxId = jdbcTemplate.queryForObject(
                "SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);

        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        sb.setToolName("SBOMPlatform");
        sb.setToolVersion("1.0.0");
        sb.setComponents(comps);
        sb.setDependencies(deps);
        sb.setSource(sourceInfo);

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

        // 计算当前最大 ID，并将 AUTO_INCREMENT 设为 max+1
        Integer maxId = jdbcTemplate.queryForObject(
                "SELECT COALESCE(MAX(id), 0) FROM sbom", Integer.class);
        int next = (maxId == null ? 1 : maxId + 1);
        jdbcTemplate.execute("ALTER TABLE sbom AUTO_INCREMENT = " + next);
    }

    // 增强许可证信息
    private void enhanceLicenseInfo(List<Component> components) {
        for (Component comp : components) {
            if (comp.getLicense() == null) {
                // 尝试基于常见命名约定猜测许可证
                if (comp.getName() != null) {
                    String name = comp.getName().toLowerCase();
                    if (name.contains("apache")) {
                        comp.setLicense("Apache-2.0");
                    } else if (name.contains("mit")) {
                        comp.setLicense("MIT");
                    } else if (name.contains("gpl")) {
                        comp.setLicense("GPL-3.0");
                    } else if (name.contains("lgpl")) {
                        comp.setLicense("LGPL-3.0");
                    } else if (name.contains("bsd")) {
                        comp.setLicense("BSD-3-Clause");
                    }
                }
            }
        }
    }

    // 增强Maven元数据
    private void enrichMavenMetadata(List<Component> components) {
        for (Component comp : components) {
            // 如果已有purl，解析并补充信息
            if (comp.getPurl() != null && comp.getPurl().startsWith("pkg:maven/")) {
                // 示例：pkg:maven/group/artifact@version
                String purl = comp.getPurl();
                String[] parts = purl.substring("pkg:maven/".length()).split("@");
                if (parts.length == 2) {
                    String[] groupArtifact = parts[0].split("/");
                    if (groupArtifact.length == 2) {
                        String groupId = groupArtifact[0];
                        String artifactId = groupArtifact[1];

                        // 如果没有供应商，使用groupId作为供应商
                        if (comp.getVendor() == null) {
                            comp.setVendor(groupId);
                        }

                        // 如果没有主页，构造一个可能的Maven中央库链接
                        if (comp.getHomePage() == null) {
                            comp.setHomePage("https://search.maven.org/artifact/" +
                                    groupId + "/" + artifactId);
                        }
                    }
                }
            }
        }
    }

    // 构建依赖关系
    private List<Dependency> buildDependencies(List<Component> components) {
        // 创建一个简单的依赖图
        // 这里简化处理，仅基于JAR文件名创建一些模拟依赖关系
        List<Dependency> dependencies = new ArrayList<>();

        // 创建一个主系统组件作为根节点
        if (!components.isEmpty()) {
            Dependency rootDep = new Dependency();
            rootDep.setRef("system");

            // 所有直接依赖
            List<String> directDeps = new ArrayList<>();
            for (Component comp : components) {
                directDeps.add(comp.getSbomRef());
            }

            rootDep.setDependsOn(directDeps);
            dependencies.add(rootDep);
        }

        return dependencies;
    }
}
