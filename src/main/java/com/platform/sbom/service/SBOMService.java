package com.platform.sbom.service;

import com.platform.sbom.converter.SBOMConverter;
import com.platform.sbom.model.*;
import com.platform.sbom.mongo.SBOMDocument;
import com.platform.sbom.mongo.SBOMDocumentRepository;
import com.platform.sbom.repository.SBOMRepository;
import lombok.extern.log4j.Log4j2;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.util.*;

@Log4j2
@Service
public class SBOMService {
    private final SBOMRepository repo;
    private final SBOMDocumentRepository docRepo;
    private final SyftService syftService;
    private final SBOMConverter converter;
    private final JdbcTemplate jdbcTemplate;
    

    public SBOMService(SBOMRepository repo, SBOMDocumentRepository docRepo, SyftService syftService,
                       SBOMConverter converter, JdbcTemplate jdbcTemplate) {
        this.repo = repo;
        this.docRepo = docRepo;
        this.syftService = syftService;
        this.converter = converter;
        this.jdbcTemplate = jdbcTemplate;
        
    }

    public boolean existsById(Long id) {
        return repo.existsById(id);
    }

    public List<SBOM> listAll() {
        return repo.findAll();
    }

    /**
     * 获取所有SBOM列表
     * @return SBOM列表
     */
    public List<SBOM> getAllSBOMs() {
        return listAll();
    }

    /**
     * 根据ID获取SBOM
     * @param id SBOM的ID
     * @return 包含SBOM的Optional对象
     */
    public Optional<SBOM> getSBOMById(Long id) {
        return find(id);
    }

    public Optional<SBOM> find(Long id) {
        return repo.findById(id);
    }

    /**
     * 使用Syft生成SBOM，支持SPDX和CycloneDX标准
     */
    @Transactional
    public SBOM generate(String name, MultipartFile[] folder, MultipartFile img, String format) throws Exception {
        // Save files to temp directory
        File tmpF = Files.createTempDirectory("sys").toFile();
        Map<String, String> originalPaths = new HashMap<>();

        for (MultipartFile mf : folder) {
            String originalName = mf.getOriginalFilename();
            File dest = new File(tmpF, originalName);
            dest.getParentFile().mkdirs();
            mf.transferTo(dest);

            if (originalName != null) {
                originalPaths.put(dest.getAbsolutePath(), originalName);
            }
        }

        // 同时使用SPDX和CycloneDX格式生成SBOM
        log.info("同时使用SPDX和CycloneDX格式生成SBOM，以获取最全面的组件信息");
        
        // 使用SPDX格式扫描
        Map<String, Object> spdxData = syftService.scanFileSystemSPDX(tmpF.getAbsolutePath());
        List<Component> spdxComponents = (List<Component>) spdxData.get("components");
        List<Dependency> spdxDependencies = (List<Dependency>) spdxData.get("dependencies");
        log.info("SPDX格式扫描发现 {} 个组件和 {} 个依赖关系", 
                spdxComponents.size(), spdxDependencies.size());
        
        // 使用CycloneDX格式扫描
        Map<String, Object> cdxData = syftService.scanFileSystemCycloneDX(tmpF.getAbsolutePath());
        List<Component> cdxComponents = (List<Component>) cdxData.get("components");
        List<Dependency> cdxDependencies = (List<Dependency>) cdxData.get("dependencies");
        log.info("CycloneDX格式扫描发现 {} 个组件和 {} 个依赖关系", 
                cdxComponents.size(), cdxDependencies.size());
                
        // 统计组件属性情况，用于调试
        countNonEmptyProperties(spdxComponents, "SPDX组件");
        countNonEmptyProperties(cdxComponents, "CycloneDX组件");
                
        // 合并两种格式的结果
        List<Component> mergedComponents = mergeComponents(spdxComponents, cdxComponents);
        List<Dependency> mergedDependencies = mergeDependencies(spdxDependencies, cdxDependencies);
        log.info("合并后有 {} 个组件和 {} 个依赖关系", 
                mergedComponents.size(), mergedDependencies.size());
        
        // 统计合并后的情况
        countNonEmptyProperties(mergedComponents, "合并后组件");

        // 增强组件元数据
        enrichMavenMetadata(mergedComponents);
        enhanceCpeInfo(mergedComponents);
        enhanceLicenseInfo(mergedComponents);

        // 处理容器镜像（如果提供）
        if (img != null && !img.isEmpty()) {
            File tmpI = File.createTempFile("img", ".tar");
            img.transferTo(tmpI);

            // 同时使用两种格式扫描容器镜像
            // SPDX格式
            Map<String, Object> spdxImageData = syftService.scanContainerImageFromFileSPDX(tmpI);
            List<Component> spdxImageComps = (List<Component>) spdxImageData.get("components");
            List<Dependency> spdxImageDeps = (List<Dependency>) spdxImageData.get("dependencies");
            
            // CycloneDX格式
            Map<String, Object> cdxImageData = syftService.scanContainerImageFromFileCycloneDX(tmpI);
            List<Component> cdxImageComps = (List<Component>) cdxImageData.get("components");
            List<Dependency> cdxImageDeps = (List<Dependency>) cdxImageData.get("dependencies");
            
            // 合并容器镜像扫描结果
            List<Component> mergedImageComps = mergeComponents(spdxImageComps, cdxImageComps);
            List<Dependency> mergedImageDeps = mergeDependencies(spdxImageDeps, cdxImageDeps);
            
            log.info("Syft在容器镜像中发现 {} 个组件和 {} 个依赖关系", 
                    mergedImageComps.size(), mergedImageDeps.size());

            for (Component comp : mergedImageComps) {
                comp.setSourceRepo("container-image");
                if (comp.getDescription() == null) {
                    comp.setDescription("From container image");
                }
            }

            // 添加镜像中的组件和依赖关系
            mergedComponents.addAll(mergedImageComps);
            mergedDependencies.addAll(mergedImageDeps);
            
            tmpI.delete();
        }

        // 创建基于扫描源的SourceInfo
        SourceInfo sourceInfo = new SourceInfo();
        FileSystemInfo fsInfo = new FileSystemInfo(tmpF.getAbsolutePath(), true);
        sourceInfo.setFilesystem(fsInfo);

        if (img != null && !img.isEmpty()) {
            ImageInfo imgInfo = new ImageInfo(img.getOriginalFilename(), "local-upload");
            sourceInfo.setImage(imgInfo);
        }

        // 构建SBOM对象
        SBOM sb = new SBOM();
        // 手动设置ID
        Long maxId = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);
        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        
        // 设置工具名称和版本
        sb.setToolName("SBOMPlatform-Syft-Enhanced");
        sb.setToolVersion("1.0.0");
        
        // 确保依赖关系引用的组件ID与实际组件一致
        ensureDependencyConsistency(mergedComponents, mergedDependencies);
        
        sb.setComponents(mergedComponents);
        sb.setDependencies(mergedDependencies);
        sb.setSource(sourceInfo);
        
        // 设置所使用的规范标准（标记为自定义格式）
        sb.setSpecVersion("CUSTOM-ENHANCED-1.0");

        // 保存到数据库
        SBOM saved = repo.save(sb);
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));

        return saved;
    }

    /**
     * 为兼容旧接口的包装方法，使用增强版生成SBOM
     */
    @Transactional
    public SBOM generate(String name, MultipartFile[] folder, MultipartFile img) throws Exception {
        return generate(name, folder, img, "enhanced");
    }

    /**
     * 使用Syft直接为容器镜像生成SBOM
     */
    @Transactional
    public SBOM generateForContainerImage(String name, String imageName, String format) throws Exception {
        // 同时使用SPDX和CycloneDX格式生成SBOM
        log.info("同时使用SPDX和CycloneDX格式为容器镜像生成SBOM");
        
        // 使用SPDX格式扫描
        Map<String, Object> spdxData = syftService.scanContainerImageSPDX(imageName);
        List<Component> spdxComponents = (List<Component>) spdxData.get("components");
        List<Dependency> spdxDependencies = (List<Dependency>) spdxData.get("dependencies");
        log.info("SPDX格式扫描容器镜像 {} 发现 {} 个组件和 {} 个依赖关系", 
                imageName, spdxComponents.size(), spdxDependencies.size());
        
        // 使用CycloneDX格式扫描
        Map<String, Object> cdxData = syftService.scanContainerImageCycloneDX(imageName);
        List<Component> cdxComponents = (List<Component>) cdxData.get("components");
        List<Dependency> cdxDependencies = (List<Dependency>) cdxData.get("dependencies");
        log.info("CycloneDX格式扫描容器镜像 {} 发现 {} 个组件和 {} 个依赖关系", 
                imageName, cdxComponents.size(), cdxDependencies.size());
                
        // 统计组件属性情况，用于调试
        countNonEmptyProperties(spdxComponents, "SPDX容器镜像组件");
        countNonEmptyProperties(cdxComponents, "CycloneDX容器镜像组件");
                
        // 合并两种格式的结果
        List<Component> mergedComponents = mergeComponents(spdxComponents, cdxComponents);
        List<Dependency> mergedDependencies = mergeDependencies(spdxDependencies, cdxDependencies);
        log.info("合并后有 {} 个组件和 {} 个依赖关系", 
                mergedComponents.size(), mergedDependencies.size());
                
        // 统计合并后的情况
        countNonEmptyProperties(mergedComponents, "合并后容器镜像组件");

        // 增强组件元数据
        enrichMavenMetadata(mergedComponents);
        enhanceCpeInfo(mergedComponents);
        enhanceLicenseInfo(mergedComponents);

        // 创建source info
        SourceInfo sourceInfo = syftService.createSourceInfo(null, imageName, null);

        // 构建SBOM对象
        SBOM sb = new SBOM();
        // 手动设置ID
        Long maxId = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);
        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        
        // 设置工具名称和版本
        sb.setToolName("SBOMPlatform-Syft-Enhanced");
        sb.setToolVersion("1.0.0");
        
        // 确保依赖关系引用的组件ID与实际组件一致
        ensureDependencyConsistency(mergedComponents, mergedDependencies);
        
        sb.setComponents(mergedComponents);
        sb.setDependencies(mergedDependencies);
        sb.setSource(sourceInfo);
        
        // 设置所使用的规范标准（标记为自定义格式）
        sb.setSpecVersion("CUSTOM-ENHANCED-1.0");

        // 保存到数据库
        SBOM saved = repo.save(sb);
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));

        return saved;
    }
    
    /**
     * 为兼容旧接口的包装方法，使用增强版生成SBOM
     */
    @Transactional
    public SBOM generateForContainerImage(String name, String imageName) throws Exception {
        return generateForContainerImage(name, imageName, "enhanced");
    }

    @Transactional
    public void delete(Long id) {
        docRepo.deleteBySbomId(id);
        repo.deleteById(id);

        // Reset auto-increment
        Integer maxId = jdbcTemplate.queryForObject(
                "SELECT COALESCE(MAX(id), 0) FROM sbom", Integer.class);
        int next = (maxId == null ? 1 : maxId + 1);
        jdbcTemplate.execute("ALTER TABLE sbom AUTO_INCREMENT = " + next);
    }

    //扫描syft生成json中的license字段，如果为空，则设置为unknown
    private void enhanceLicenseInfo(List<Component> components) {
        for (Component comp : components) {
            if (comp.getLicense() == null || comp.getLicense().isEmpty()) {
                comp.setLicense("unknown");
            }
        }
    }
    
    // Enhance Maven metadata
    private void enrichMavenMetadata(List<Component> components) {
        for (Component comp : components) {
            // If PURL exists, parse and supplement information
            if (comp.getPurl() != null && comp.getPurl().startsWith("pkg:maven/")) {
                // Example: pkg:maven/group/artifact@version
                String purl = comp.getPurl();
                String[] parts = purl.substring("pkg:maven/".length()).split("@");
                if (parts.length == 2) {
                    String[] groupArtifact = parts[0].split("/");
                    if (groupArtifact.length == 2) {
                        String groupId = groupArtifact[0];
                        String artifactId = groupArtifact[1];

                        // Use groupId as vendor if not present
                        if (comp.getVendor() == null) {
                            comp.setVendor(groupId);
                        }

                        // Construct potential Maven Central URL if homepage not present
                        if (comp.getHomePage() == null) {
                            comp.setHomePage("https://search.maven.org/artifact/" +
                                    groupId + "/" + artifactId);
                        }
                    }
                }
            }
        }
    }

    // 添加 enhanceCpeInfo 方法
    private void enhanceCpeInfo(List<Component> components) {
        for (Component comp : components) {
            if (comp.getCpe() == null || comp.getCpe().isEmpty()) {
                if (comp.getPurl() != null) {
                    // 假设 PURL 格式为 pkg:type/group/name@version
                    String purl = comp.getPurl();
                    String[] parts = purl.split(":");
                    if (parts.length > 2) {
                        String[] groupName = parts[2].split("/");
                        if (groupName.length > 1) {
                            String vendor = groupName[0];
                            String product = groupName[1];
                            String version = comp.getVersion() != null ? comp.getVersion() : "unknown";
                            // 生成 CPE 字段
                            comp.setCpe(String.format("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version));
                        }
                    }
                } else {
                    // 如果 PURL 缺失，设置默认值或提示
                    comp.setCpe("UNKNOWN");
                }
            }
        }
    }

    /**
     * 合并两种不同格式(SPDX和CycloneDX)的组件数据，取两者的优势
     * @param spdxComponents SPDX格式生成的组件列表
     * @param cdxComponents CycloneDX格式生成的组件列表
     * @return 合并后的组件列表
     */
    private List<Component> mergeComponents(List<Component> spdxComponents, List<Component> cdxComponents) {
        if (spdxComponents == null || spdxComponents.isEmpty()) {
            return cdxComponents != null ? new ArrayList<>(cdxComponents) : new ArrayList<>();
        }
        
        if (cdxComponents == null || cdxComponents.isEmpty()) {
            return new ArrayList<>(spdxComponents);
        }
        
        // 使用更精确的唯一标识符
        Map<String, Component> mergedMap = new HashMap<>();
        Map<String, Component> spdxMap = new HashMap<>();
        Map<String, Component> cdxMap = new HashMap<>();
        
        // 添加所有SPDX组件到结果和映射表
        for (Component comp : spdxComponents) {
            String key = generateComponentKey(comp);
            mergedMap.put(key, comp);
            spdxMap.put(key, comp);
        }
        
        // 处理CycloneDX组件
        for (Component cdxComp : cdxComponents) {
            String key = generateComponentKey(cdxComp);
            cdxMap.put(key, cdxComp);
            
            Component existing = mergedMap.get(key);
            if (existing == null) {
                // 如果SPDX中没有此组件，直接添加CycloneDX组件
                mergedMap.put(key, cdxComp);
            } else {
                // 合并两种组件信息，优先使用非空值
                mergeComponentProperties(existing, cdxComp);
            }
        }
        
        // 检查是否有组件被错误合并，使用更多属性进行比较
        for (Component cdxComp : cdxComponents) {
            // 检查是否有错误合并的情况（如果存在相同名称和版本但其他关键属性不同的组件）
            String key = generateComponentKey(cdxComp);
            if (!mergedMap.containsKey(key)) continue; // 已经处理过或无匹配项
            
            Component existingComp = mergedMap.get(key);
            // 检查关键属性是否有显著差异
            if (hasMajorDifferences(existingComp, cdxComp)) {
                // 关键属性差异大，应该是不同组件，生成新的唯一键
                String uniqueKey = key + "-" + cdxComp.hashCode();
                mergedMap.put(uniqueKey, cdxComp);
            }
        }
        
        log.info("合并组件 - SPDX: {}, CycloneDX: {}, 合并后: {}", 
                spdxComponents.size(), cdxComponents.size(), mergedMap.size());
        
        return new ArrayList<>(mergedMap.values());
    }
    
    /**
     * 生成组件的唯一标识键
     */
    private String generateComponentKey(Component comp) {
        String baseKey = (comp.getName() + ":" + comp.getVersion()).toLowerCase();
        
        // 如果有更精确的标识符如purl，优先使用
        if (comp.getPurl() != null && !comp.getPurl().isEmpty()) {
            return "purl:" + comp.getPurl().toLowerCase();
        } else if (comp.getSbomRef() != null && !comp.getSbomRef().isEmpty() && !comp.getSbomRef().equals("system")) {
            return "ref:" + comp.getSbomRef().toLowerCase();
        }
        
        // 如果类型可用，添加到键中增加唯一性
        if (comp.getType() != null && !comp.getType().isEmpty()) {
            baseKey = comp.getType().toLowerCase() + ":" + baseKey;
        }
        
        return baseKey;
    }
    
    /**
     * 检查两个组件是否有显著差异
     */
    private boolean hasMajorDifferences(Component comp1, Component comp2) {
        // 如果存在purl且不同，则认为是不同组件
        if (comp1.getPurl() != null && comp2.getPurl() != null && 
            !comp1.getPurl().isEmpty() && !comp2.getPurl().isEmpty() && 
            !comp1.getPurl().equalsIgnoreCase(comp2.getPurl())) {
            return true;
        }
        
        // 检查来源和路径差异
        if (comp1.getSourceRepo() != null && comp2.getSourceRepo() != null &&
            !comp1.getSourceRepo().isEmpty() && !comp2.getSourceRepo().isEmpty() &&
            !comp1.getSourceRepo().equalsIgnoreCase(comp2.getSourceRepo())) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 合并组件属性，优先使用非空值
     */
    private void mergeComponentProperties(Component target, Component source) {
        if (isEmpty(target.getLicense()) && !isEmpty(source.getLicense())) {
            target.setLicense(source.getLicense());
        }
        
        if (isEmpty(target.getPurl()) && !isEmpty(source.getPurl())) {
            target.setPurl(source.getPurl());
        }
        
        if (isEmpty(target.getCpe()) && !isEmpty(source.getCpe())) {
            target.setCpe(source.getCpe());
        }
        
        if (isEmpty(target.getVendor()) && !isEmpty(source.getVendor())) {
            target.setVendor(source.getVendor());
        }
        
        if (isEmpty(target.getHomePage()) && !isEmpty(source.getHomePage())) {
            target.setHomePage(source.getHomePage());
        }
        
        if (isEmpty(target.getDescription()) && !isEmpty(source.getDescription())) {
            target.setDescription(source.getDescription());
        }
    }
    
    /**
     * 合并两个依赖列表
     * @param spdxDeps SPDX格式的依赖列表
     * @param cdxDeps CycloneDX格式的依赖列表
     * @return 合并后的依赖列表
     */
    private List<Dependency> mergeDependencies(List<Dependency> spdxDeps, List<Dependency> cdxDeps) {
        if (spdxDeps == null || spdxDeps.isEmpty()) {
            return cdxDeps != null ? new ArrayList<>(cdxDeps) : new ArrayList<>();
        }
        
        if (cdxDeps == null || cdxDeps.isEmpty()) {
            return new ArrayList<>(spdxDeps);
        }
        
        // 使用Map来存储合并的依赖
        Map<String, Dependency> mergedDeps = new HashMap<>();
        
        // 首先添加所有SPDX依赖
        for (Dependency dep : spdxDeps) {
            mergedDeps.put(dep.getRef(), dep);
        }
        
        // 然后处理CycloneDX依赖
        for (Dependency cdxDep : cdxDeps) {
            String ref = cdxDep.getRef();
            if (mergedDeps.containsKey(ref)) {
                // 合并依赖关系
                Dependency existingDep = mergedDeps.get(ref);
                mergeDependsOn(existingDep, cdxDep);
            } else {
                // 添加新的依赖
                mergedDeps.put(ref, cdxDep);
            }
        }
        
        log.info("合并依赖 - SPDX: {}, CycloneDX: {}, 合并后: {}", 
                spdxDeps.size(), cdxDeps.size(), mergedDeps.size());
        
        return new ArrayList<>(mergedDeps.values());
    }
    
    /**
     * 合并依赖关系的dependsOn列表
     */
    private void mergeDependsOn(Dependency target, Dependency source) {
        if (source.getDependsOn() == null || source.getDependsOn().isEmpty()) {
            return;
        }
        
        if (target.getDependsOn() == null) {
            target.setDependsOn(new ArrayList<>());
        }
        
        // 合并依赖，避免重复
        for (String dependency : source.getDependsOn()) {
            if (!target.getDependsOn().contains(dependency)) {
                target.getDependsOn().add(dependency);
            }
        }
    }
    
    /**
     * 辅助方法：检查字符串是否为空
     */
    private boolean isEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    private void countNonEmptyProperties(List<Component> components, String prefix) {
        int count = 0;
        for (Component comp : components) {
            if (comp.getName() != null && !comp.getName().isEmpty()) count++;
            if (comp.getVersion() != null && !comp.getVersion().isEmpty()) count++;
            if (comp.getPurl() != null && !comp.getPurl().isEmpty()) count++;
            if (comp.getSbomRef() != null && !comp.getSbomRef().isEmpty()) count++;
            if (comp.getType() != null && !comp.getType().isEmpty()) count++;
            if (comp.getVendor() != null && !comp.getVendor().isEmpty()) count++;
            if (comp.getHomePage() != null && !comp.getHomePage().isEmpty()) count++;
            if (comp.getDescription() != null && !comp.getDescription().isEmpty()) count++;
            if (comp.getLicense() != null && !comp.getLicense().isEmpty()) count++;
            if (comp.getCpe() != null && !comp.getCpe().isEmpty()) count++;
        }
        log.info("{} 组件中非空属性数量: {}", prefix, count);
    }

    /**
     * 确保依赖关系引用的组件ID与实际组件一致
     * @param components 组件列表
     * @param dependencies 依赖关系列表
     */
    private void ensureDependencyConsistency(List<Component> components, List<Dependency> dependencies) {
        if (components == null || dependencies == null || components.isEmpty() || dependencies.isEmpty()) {
            return;
        }
        
        // 为所有组件创建映射，优先使用sbomRef作为标识
        Map<String, Component> componentMap = new HashMap<>();
        for (Component comp : components) {
            if (comp.getSbomRef() != null && !comp.getSbomRef().isEmpty()) {
                componentMap.put(comp.getSbomRef(), comp);
            }
        }
        
        // 检查每个依赖关系，确保引用的组件存在
        Set<String> validRefs = componentMap.keySet();
        List<Dependency> validDependencies = new ArrayList<>();
        
        for (Dependency dep : dependencies) {
            // 检查依赖关系的引用是否存在于组件中
            if (dep.getRef() != null && (validRefs.contains(dep.getRef()) || dep.getRef().equals("system"))) {
                // 检查dependsOn列表
                if (dep.getDependsOn() != null && !dep.getDependsOn().isEmpty()) {
                    List<String> validDependsOn = new ArrayList<>();
                    for (String dependsOnRef : dep.getDependsOn()) {
                        if (validRefs.contains(dependsOnRef)) {
                            validDependsOn.add(dependsOnRef);
                        }
                    }
                    dep.setDependsOn(validDependsOn);
                }
                
                if (dep.getDependsOn() == null || !dep.getDependsOn().isEmpty()) {
                    validDependencies.add(dep);
                }
            }
        }
        
        // 如果有无效的依赖关系，记录并替换
        if (validDependencies.size() < dependencies.size()) {
            log.info("过滤了 {} 个无效的依赖关系（引用了不存在的组件）", 
                    dependencies.size() - validDependencies.size());
            dependencies.clear();
            dependencies.addAll(validDependencies);
        }
    }
}