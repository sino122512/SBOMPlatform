package com.platform.sbom.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.platform.sbom.model.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Log4j2
@Service
public class SyftService {

    private final ObjectMapper objectMapper;

    @Value("${syft.path:C:/Users/12135/scoop/apps/syft/current/syft.exe}")
    private String syftPath;

    public SyftService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * 使用Syft生成SBOM并扫描文件系统目录 (SPDX格式)
     *
     * @param directory 要扫描的目录
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanFileSystemSPDX(String directory) {
        return runSyftScan(directory, null, "spdx-json");
    }

    /**
     * 使用Syft生成SBOM并扫描容器镜像 (SPDX格式)
     *
     * @param imageName 要扫描的镜像名称（例如，alpine:latest）
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanContainerImageSPDX(String imageName) {
        return runSyftScan(null, imageName, "spdx-json");
    }

    /**
     * 使用Syft从容器镜像tar文件生成SBOM (SPDX格式)
     *
     * @param imageFile 包含容器镜像的tar文件
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanContainerImageFromFileSPDX(File imageFile) {
        return runSyftScan("docker-archive:" + imageFile.getAbsolutePath(), null, "spdx-json");
    }

    /**
     * 使用Syft生成SBOM并扫描文件系统目录 (CycloneDX格式)
     *
     * @param directory 要扫描的目录
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanFileSystemCycloneDX(String directory) {
        return runSyftScan(directory, null, "cyclonedx-json");
    }

    /**
     * 使用Syft生成SBOM并扫描容器镜像 (CycloneDX格式)
     *
     * @param imageName 要扫描的镜像名称（例如，alpine:latest）
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanContainerImageCycloneDX(String imageName) {
        return runSyftScan(null, imageName, "cyclonedx-json");
    }

    /**
     * 使用Syft从容器镜像tar文件生成SBOM (CycloneDX格式)
     *
     * @param imageFile 包含容器镜像的tar文件
     * @return 包含组件和依赖关系的结果Map
     */
    public Map<String, Object> scanContainerImageFromFileCycloneDX(File imageFile) {
        return runSyftScan("docker-archive:" + imageFile.getAbsolutePath(), null, "cyclonedx-json");
    }

    /**
     * 执行Syft并生成指定格式的SBOM，然后解析组件和依赖关系
     *
     * @param source 目录路径、docker-archive路径或null
     * @param imageName 容器镜像名称或null
     * @param format SBOM格式，支持 "spdx-json" 或 "cyclonedx-json"
     * @return 包含组件列表和依赖关系列表的Map
     */
    private Map<String, Object> runSyftScan(String source, String imageName, String format) {
        Map<String, Object> result = new HashMap<>();
        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();
        String sbomFormat = format.toLowerCase();
        
        try {
            // 创建临时文件用于存储JSON输出
            Path tempFile = Files.createTempFile("syft-" + sbomFormat + "-", ".json");
            
            ProcessBuilder pb = new ProcessBuilder();
            List<String> command = new ArrayList<>();
            command.add(syftPath);
            command.add("packages");

            // 设置源（目录、镜像或存档）
            if (source != null) {
                command.add(source);
            } else if (imageName != null) {
                command.add(imageName);
            }

            // 输出为指定JSON格式并保存到临时文件
            command.add("-o");
            command.add(sbomFormat);
            command.add("--file");
            command.add(tempFile.toString());

            log.info("执行Syft命令生成 {}: {}", sbomFormat, String.join(" ", command));
            pb.command(command);

            Process process = pb.start();
            int exitCode = process.waitFor();
            
            if (exitCode == 0) {
                // 读取JSON文件
                String sbomJson = Files.readString(tempFile);
                
                // 根据格式解析JSON，提取组件和依赖关系
                Map<String, Object> parsedData;
                if (sbomFormat.startsWith("spdx")) {
                    parsedData = parseSPDXOutput(sbomJson, source, imageName);
                } else if (sbomFormat.startsWith("cyclonedx")) {
                    parsedData = parseCycloneDXOutput(sbomJson, source, imageName);
                } else {
                    throw new IllegalArgumentException("不支持的SBOM格式: " + sbomFormat);
                }
                
                components = (List<Component>) parsedData.get("components");
                dependencies = (List<Dependency>) parsedData.get("dependencies");
                
                log.info("成功从{}解析出 {} 个组件和 {} 个依赖关系", 
                        sbomFormat, components.size(), dependencies.size());
            } else {
                log.error("Syft执行失败，退出代码: {}", exitCode);
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                String line;
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }
                log.error("Syft错误: {}", errorOutput.toString());
            }
            
            // 清理临时文件
            Files.deleteIfExists(tempFile);
            
        } catch (Exception e) {
            log.error("执行Syft时出错", e);
        }
        
        result.put("components", components);
        result.put("dependencies", dependencies);
        return result;
    }

    /**
     * 解析SPDX JSON输出为组件对象和依赖关系
     *
     * @param json SPDX JSON输出
     * @param source 被扫描的源
     * @param imageName 被扫描的镜像名称
     * @return 包含组件列表和依赖关系列表的Map
     */
    private Map<String, Object> parseSPDXOutput(String json, String source, String imageName) {
        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();
        Map<String, Component> componentMap = new HashMap<>();
        
        try {
            JsonNode root = objectMapper.readTree(json);
            
            // 解析SPDX文档信息
            String documentName = root.path("name").asText("Unknown SBOM");
            log.info("解析SPDX文档: {}", documentName);
            
            // 解析包描述
            JsonNode packages = root.path("packages");
            if (packages != null && packages.isArray()) {
                for (JsonNode pkg : packages) {
                    // 跳过文档自身包
                    if (pkg.path("SPDXID").asText().equals("SPDXRef-DOCUMENT")) {
                        continue;
                    }
                    
                    Component component = new Component();
                    
                    // 提取包ID (SPDXID)
                    String spdxId = pkg.path("SPDXID").asText("").replace("SPDXRef-", "");
                    component.setSbomRef(spdxId);
                    
                    // 提取基本组件信息
                    component.setName(pkg.path("name").asText(""));
                    component.setVersion(pkg.path("versionInfo").asText(""));
                    
                    // 提取供应商
                    component.setVendor(pkg.path("supplier").asText(""));
                    
                    // 提取许可证
                    String licenseConcluded = pkg.path("licenseConcluded").asText("");
                    String licenseDeclared = pkg.path("licenseDeclared").asText("");
                    component.setLicense(!licenseConcluded.isEmpty() ? licenseConcluded : 
                                        (!licenseDeclared.isEmpty() ? licenseDeclared : "UNKNOWN"));
                    
                    // 提取描述
                    component.setDescription(pkg.path("description").asText(""));
                    
                    // 提取类型
                    component.setType(pkg.path("primaryPackagePurpose").asText("LIBRARY"));
                    
                    // 提取PURL
                    JsonNode externalRefs = pkg.path("externalRefs");
                    if (externalRefs != null && externalRefs.isArray()) {
                        for (JsonNode ref : externalRefs) {
                            String refType = ref.path("referenceType").asText("");
                            if (refType.equals("purl")) {
                                component.setPurl(ref.path("referenceLocator").asText(""));
                                break;
                            }
                        }
                    }
                    
                    // 提取CPE
                    if (externalRefs != null && externalRefs.isArray()) {
                        for (JsonNode ref : externalRefs) {
                            String refType = ref.path("referenceType").asText("");
                            if (refType.equals("cpe23Type") || refType.equals("cpe22Type")) {
                                component.setCpe(ref.path("referenceLocator").asText(""));
                                break;
                            }
                        }
                    }
                    
                    // 设置基于源的元数据
                    if (imageName != null) {
                        component.setSourceRepo("container-image:" + imageName);
                    } else if (source != null) {
                        if (source.startsWith("docker-archive:")) {
                            component.setSourceRepo("container-image-archive");
                        } else {
                            component.setSourceRepo("filesystem:" + source);
                        }
                    }
                    
                    components.add(component);
                    componentMap.put(spdxId, component);

                    // 如果没有找到许可证信息，设置默认值
                    if (component.getLicense() == null || component.getLicense().isEmpty()) {
                        component.setLicense("UNKNOWN");
                    }
                }
            }
            
            // 解析依赖关系
            JsonNode relationships = root.path("relationships");
            if (relationships != null && relationships.isArray()) {
                for (JsonNode rel : relationships) {
                    String relationType = rel.path("relationshipType").asText("");
                    
                    // 仅处理DEPENDS_ON关系
                    if (relationType.equals("DEPENDS_ON")) {
                        String sourceId = rel.path("spdxElementId").asText("").replace("SPDXRef-", "");
                        String targetId = rel.path("relatedSpdxElement").asText("").replace("SPDXRef-", "");
                        
                        // 检查是否已存在此源的依赖关系
                        Dependency existingDep = null;
                        for (Dependency dep : dependencies) {
                            if (dep.getRef().equals(sourceId)) {
                                existingDep = dep;
                                break;
                            }
                        }
                        
                        if (existingDep == null) {
                            // 创建新的依赖关系
                            Dependency dep = new Dependency();
                            dep.setRef(sourceId);
                            List<String> dependsOn = new ArrayList<>();
                            dependsOn.add(targetId);
                            dep.setDependsOn(dependsOn);
                            dependencies.add(dep);
                        } else {
                            // 向现有依赖关系添加目标
                            existingDep.getDependsOn().add(targetId);
                        }
                    }
                }
            }
            
            // 如果没有找到依赖关系，创建基于组件的简单依赖树
            if (dependencies.isEmpty() && !components.isEmpty()) {
                log.info("未找到依赖关系，创建系统级依赖树");
                Dependency rootDep = new Dependency();
                rootDep.setRef("system");
                
                List<String> allComponents = new ArrayList<>();
                for (Component comp : components) {
                    allComponents.add(comp.getSbomRef());
                }
                
                rootDep.setDependsOn(allComponents);
                dependencies.add(rootDep);
            }
            
        } catch (Exception e) {
            log.error("解析SPDX输出时出错", e);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("components", components);
        result.put("dependencies", dependencies);
        return result;
    }

    /**
     * 解析CycloneDX JSON输出为组件对象和依赖关系
     *
     * @param json CycloneDX JSON输出
     * @param source 被扫描的源
     * @param imageName 被扫描的镜像名称
     * @return 包含组件列表和依赖关系列表的Map
     */
    private Map<String, Object> parseCycloneDXOutput(String json, String source, String imageName) {
        List<Component> components = new ArrayList<>();
        List<Dependency> dependencies = new ArrayList<>();
        Map<String, Component> componentMap = new HashMap<>();
        
        try {
            JsonNode root = objectMapper.readTree(json);
            
            // 解析CycloneDX元数据
            JsonNode metadata = root.path("metadata");
            String documentName = metadata.path("component").path("name").asText("Unknown SBOM");
            log.info("解析CycloneDX文档: {}", documentName);
            
            // 解析组件
            JsonNode cdxComponents = root.path("components");
            if (cdxComponents != null && cdxComponents.isArray()) {
                for (JsonNode cdxComp : cdxComponents) {
                    Component component = new Component();
                    
                    // 提取基本组件信息
                    component.setName(cdxComp.path("name").asText(""));
                    component.setVersion(cdxComp.path("version").asText(""));
                    
                    // 提取类型
                    component.setType(cdxComp.path("type").asText(""));
                    
                    // 提取BOM引用ID
                    String bomRef = cdxComp.path("bom-ref").asText("");
                    if (bomRef.isEmpty()) {
                        // 如果没有bom-ref, 生成一个基于类型/名称/版本的ID
                        bomRef = "pkg:" + component.getType() + "/" + component.getName() + "@" + component.getVersion();
                    }
                    component.setSbomRef(bomRef);
                    
                    // 提取供应商
                    JsonNode supplier = cdxComp.path("publisher");
                    if (!supplier.isMissingNode()) {
                        component.setVendor(supplier.asText(""));
                    }
                    
                    // 提取许可证
                    JsonNode licenses = cdxComp.path("licenses");
                    if (licenses != null && licenses.isArray() && licenses.size() > 0) {
                        JsonNode license = licenses.get(0);
                        if (license.has("license")) {
                            JsonNode licenseData = license.path("license");
                            if (licenseData.has("id")) {
                                component.setLicense(licenseData.path("id").asText(""));
                            } else if (licenseData.has("name")) {
                                component.setLicense(licenseData.path("name").asText(""));
                            }
                        } else if (license.has("expression")) {
                            component.setLicense(license.path("expression").asText(""));
                        }
                    }
                    
                    // 提取描述
                    component.setDescription(cdxComp.path("description").asText(""));
                    
                    // 提取PURL
                    JsonNode purl = cdxComp.path("purl");
                    if (!purl.isMissingNode()) {
                        component.setPurl(purl.asText(""));
                    }
                    
                    // 提取CPE
                    JsonNode cpe = cdxComp.path("cpe");
                    if (!cpe.isMissingNode()) {
                        component.setCpe(cpe.asText(""));
                    }
                    
                    // 设置基于源的元数据
                    if (imageName != null) {
                        component.setSourceRepo("container-image:" + imageName);
                    } else if (source != null) {
                        if (source.startsWith("docker-archive:")) {
                            component.setSourceRepo("container-image-archive");
                        } else {
                            component.setSourceRepo("filesystem:" + source);
                        }
                    }
                    
                    components.add(component);
                    componentMap.put(bomRef, component);

                    // 如果没有找到许可证信息，设置默认值
                    if (component.getLicense() == null || component.getLicense().isEmpty()) {
                        component.setLicense("UNKNOWN");
                    }
                }
            }
            
            // 解析依赖关系
            JsonNode cdxDependencies = root.path("dependencies");
            if (cdxDependencies != null && cdxDependencies.isArray()) {
                for (JsonNode cdxDep : cdxDependencies) {
                    String ref = cdxDep.path("ref").asText("");
                    JsonNode dependsOn = cdxDep.path("dependsOn");
                    
                    if (!ref.isEmpty() && dependsOn != null && dependsOn.isArray() && dependsOn.size() > 0) {
                        Dependency dep = new Dependency();
                        dep.setRef(ref);
                        
                        List<String> deps = new ArrayList<>();
                        for (JsonNode target : dependsOn) {
                            deps.add(target.asText());
                        }
                        
                        dep.setDependsOn(deps);
                        dependencies.add(dep);
                    }
                }
            }
            
            // 如果没有找到依赖关系，创建基于组件的简单依赖树
            if (dependencies.isEmpty() && !components.isEmpty()) {
                log.info("未找到依赖关系，创建系统级依赖树");
                Dependency rootDep = new Dependency();
                rootDep.setRef("system");
                
                List<String> allComponents = new ArrayList<>();
                for (Component comp : components) {
                    allComponents.add(comp.getSbomRef());
                }
                
                rootDep.setDependsOn(allComponents);
                dependencies.add(rootDep);
            }
            
        } catch (Exception e) {
            log.error("解析CycloneDX输出时出错", e);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("components", components);
        result.put("dependencies", dependencies);
        return result;
    }

    /**
     * Create a SourceInfo object based on the scan source
     *
     * @param directory Directory that was scanned or null
     * @param imageName Image name that was scanned or null
     * @param imageFile Image file that was scanned or null
     * @return SourceInfo object
     */
    public SourceInfo createSourceInfo(String directory, String imageName, File imageFile) {
        SourceInfo sourceInfo = new SourceInfo();

        if (directory != null) {
            FileSystemInfo fsInfo = new FileSystemInfo(directory, true);
            sourceInfo.setFilesystem(fsInfo);
        }

        if (imageName != null) {
            ImageInfo imgInfo = new ImageInfo(imageName, "registry");
            sourceInfo.setImage(imgInfo);
        } else if (imageFile != null) {
            ImageInfo imgInfo = new ImageInfo(imageFile.getName(), "local-file");
            sourceInfo.setImage(imgInfo);
        }

        return sourceInfo;
    }
}