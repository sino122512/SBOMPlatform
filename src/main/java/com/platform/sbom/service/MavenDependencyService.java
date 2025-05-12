package com.platform.sbom.service;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Maven依赖树解析服务
 */
@Service
public class MavenDependencyService {
    private static final Logger logger = Logger.getLogger(MavenDependencyService.class.getName());

    /**
     * 执行Maven依赖树命令并解析结果
     * @param projectPath Maven项目路径
     * @return Maven依赖树数据
     */
    public Map<String, Object> analyzeMavenDependencies(String projectPath) throws Exception {
        logger.info("开始分析Maven项目: " + projectPath);
        
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> links = new ArrayList<>();
        Map<String, String> nodeIdMap = new HashMap<>();
        Map<String, Integer> dependencyCount = new HashMap<>(); // 记录依赖的被引用次数
        
        // 验证项目路径和pom.xml文件
        File pomFile = new File(projectPath, "pom.xml");
        if (!pomFile.exists() || !pomFile.isFile()) {
            throw new Exception("在指定路径找不到有效的pom.xml文件: " + pomFile.getAbsolutePath());
        }
        
        logger.info("找到pom.xml文件: " + pomFile.getAbsolutePath());
        
        // 预先检查POM文件是否包含依赖项
        boolean hasDependencies = checkPomHasDependencies(pomFile);
        if (!hasDependencies) {
            logger.info("POM文件不包含依赖项，创建基本依赖图");
            return createEmptyDependencyGraph(pomFile);
        }
        
        // 使用Maven Wrapper而非直接使用mvn命令
        String mvnCommand = getMavenCommand(projectPath);
        logger.info("使用Maven命令: " + mvnCommand);
        
        // 检查是否有效的Maven项目结构，如果不是，创建临时Maven项目结构
        boolean isValidMavenStructure = checkValidMavenStructure(projectPath);
        if (!isValidMavenStructure) {
            logger.info("不是标准Maven项目结构，创建临时Maven项目结构");
            projectPath = createTemporaryMavenProject(pomFile);
        }
        
        // 首先运行mvn help:evaluate命令来测试Maven是否可用和项目是否有效
        try {
            ProcessBuilder testBuilder = new ProcessBuilder(mvnCommand, "help:evaluate", "-Dexpression=project.groupId", "-q", "-DforceStdout");
            testBuilder.directory(new File(projectPath));
            testBuilder.redirectErrorStream(true);
            
            Process testProcess = testBuilder.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(testProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            int exitCode = testProcess.waitFor();
            if (exitCode != 0) {
                logger.warning("Maven命令测试失败，尝试使用系统Maven: " + output.toString());
                // 尝试使用系统安装的Maven
                mvnCommand = isWindows() ? "mvn.cmd" : "mvn";
                
                // 重新测试
                testBuilder = new ProcessBuilder(mvnCommand, "help:evaluate", "-Dexpression=project.groupId", "-q", "-DforceStdout");
                testBuilder.directory(new File(projectPath));
                testBuilder.redirectErrorStream(true);
                
                testProcess = testBuilder.start();
                output = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(testProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                }
                
                exitCode = testProcess.waitFor();
                if (exitCode != 0) {
                    logger.warning("Maven命令仍然失败，返回简单依赖图");
                    return createEmptyDependencyGraph(pomFile);
                }
            }
            
            logger.info("Maven项目验证成功，继续处理依赖分析");
        } catch (Exception e) {
            logger.log(Level.WARNING, "Maven项目验证失败", e);
            return createEmptyDependencyGraph(pomFile);
        }
        
        // 运行dependency:tree命令获取依赖树
        ProcessBuilder processBuilder = new ProcessBuilder(mvnCommand, "dependency:tree", "-DoutputType=dot");
        processBuilder.directory(new File(projectPath));
        
        try {
            logger.info("执行命令: " + String.join(" ", processBuilder.command()));
            processBuilder.redirectErrorStream(true); // 合并标准输出和错误输出
            Process process = processBuilder.start();
            
            StringBuilder fullOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                boolean inDigraph = false;
                String rootNodeId = null;
                
                while ((line = reader.readLine()) != null) {
                    fullOutput.append(line).append("\n");
                    
                    // 标记是否进入了依赖图定义部分
                    if (line.trim().startsWith("digraph")) {
                        logger.info("找到依赖图开始标记");
                        inDigraph = true;
                        continue;
                    }
                    
                    if (line.trim().equals("}")) {
                        inDigraph = false;
                        continue;
                    }
                    
                    if (!inDigraph) continue;
                    
                    // 解析dot格式的依赖项
                    if (line.contains("->")) {
                        // 解析依赖关系行，例如: "org.springframework:spring-core" -> "org.springframework:spring-jcl"
                        Map<String, String> linkInfo = parseDependencyLine(line, links, nodeIdMap, dependencyCount);
                        
                        // 记录根节点
                        if (rootNodeId == null && linkInfo != null) {
                            rootNodeId = linkInfo.get("source");
                        }
                    } else if (line.matches(".*\".*\".*\\[.*\\].*")) {
                        // 解析节点属性行，例如: "org.springframework:spring-core" [label="spring-core\n5.3.9"]
                        parseNodeLine(line, nodes, nodeIdMap);
                    }
                }
                
                // 标记根节点
                if (rootNodeId != null) {
                    for (Map<String, Object> node : nodes) {
                        if (node.get("id").equals(nodeIdMap.get(rootNodeId))) {
                            node.put("type", "root");
                            break;
                        }
                    }
                }
                
                // 计算依赖的重要性权重（基于被引用次数）
                for (Map<String, Object> node : nodes) {
                    String artifactId = (String) node.get("artifactId");
                    int referencesCount = dependencyCount.getOrDefault(artifactId, 0);
                    node.put("weight", referencesCount);
                    
                    // 设置节点大小，基于权重
                    if (referencesCount > 0) {
                        node.put("size", Math.min(20, 10 + referencesCount * 2));
                    } else {
                        node.put("size", 10);
                    }
                }
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                logger.warning("Maven命令执行失败，退出码: " + exitCode);
                logger.warning("完整输出: " + fullOutput.toString());
                
                // 检查是否包含常见错误模式
                String output = fullOutput.toString().toLowerCase();
                if (output.contains("could not resolve dependencies") || output.contains("non-resolvable parent pom")) {
                    return createEmptyDependencyGraph(pomFile);
                } else if (output.contains("invalid content was found starting with element")) {
                    throw new Exception("POM文件格式无效，请检查XML语法是否正确。");
                } else if (output.contains("no plugin found for prefix")) {
                    throw new Exception("找不到Maven插件。请确保Maven正确安装并且能访问Maven中央仓库。");
                } else {
                    // 如果执行失败，返回基本依赖图
                    return createEmptyDependencyGraph(pomFile);
                }
            }
            
            // 如果没有发现依赖节点，可能是依赖树命令没有产生预期的输出
            if (nodes.isEmpty()) {
                logger.warning("未检测到任何依赖节点，可能是命令未产生预期输出。完整输出: " + fullOutput.toString());
                return createEmptyDependencyGraph(pomFile);
            }
            
            logger.info("成功解析到 " + nodes.size() + " 个依赖节点和 " + links.size() + " 个依赖关系");
            
            // 获取更详细的依赖信息（依赖范围等）
            enrichDependencyInfo(projectPath, nodes);
            
            Map<String, Object> result = new HashMap<>();
            result.put("nodes", nodes);
            result.put("links", links);
            return result;
        } catch (Exception e) {
            if (e.getMessage().contains("系统找不到指定的文件") || e.getMessage().contains("cannot find")) {
                logger.severe("找不到Maven执行文件: " + e.getMessage());
                return createEmptyDependencyGraph(pomFile);
            }
            logger.log(Level.SEVERE, "分析Maven依赖时出错", e);
            // 如果出错，返回基本依赖图
            return createEmptyDependencyGraph(pomFile);
        } finally {
            // 如果创建了临时项目，清理临时项目
            if (!isValidMavenStructure && !projectPath.equals(pomFile.getParent())) {
                try {
                    deleteDirectory(new File(projectPath));
                } catch (Exception e) {
                    logger.warning("清理临时Maven项目失败: " + e.getMessage());
                }
            }
        }
    }
    
    /**
     * 为空POM或解析失败的POM创建基本依赖图
     */
    private Map<String, Object> createEmptyDependencyGraph(File pomFile) {
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> links = new ArrayList<>();
        
        try {
            // 尝试解析POM文件获取基本信息
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pomFile);
            doc.getDocumentElement().normalize();
            
            String groupId = getXmlElementValue(doc, "groupId");
            String artifactId = getXmlElementValue(doc, "artifactId");
            String version = getXmlElementValue(doc, "version");
            
            // 如果无法获取项目信息，使用默认值
            if (groupId == null) groupId = "unknown.group";
            if (artifactId == null) artifactId = pomFile.getParentFile().getName();
            if (version == null) version = "unknown";
            
            // 创建根节点
            Map<String, Object> rootNode = new HashMap<>();
            rootNode.put("id", "project-root");
            rootNode.put("name", artifactId);
            rootNode.put("version", version);
            rootNode.put("groupId", groupId);
            rootNode.put("artifactId", groupId + ":" + artifactId);
            rootNode.put("type", "root");
            rootNode.put("fullName", groupId + ":" + artifactId);
            rootNode.put("size", 15);
            nodes.add(rootNode);
            
            // 尝试解析依赖
            NodeList dependencies = doc.getElementsByTagName("dependency");
            for (int i = 0; i < dependencies.getLength(); i++) {
                org.w3c.dom.Element dependency = (org.w3c.dom.Element) dependencies.item(i);
                
                String depGroupId = getXmlSubElementValue(dependency, "groupId");
                String depArtifactId = getXmlSubElementValue(dependency, "artifactId");
                String depVersion = getXmlSubElementValue(dependency, "version");
                String depScope = getXmlSubElementValue(dependency, "scope");
                
                if (depGroupId != null && depArtifactId != null) {
                    if (depVersion == null) depVersion = "unknown";
                    if (depScope == null) depScope = "compile";
                    
                    // 创建依赖节点
                    Map<String, Object> depNode = new HashMap<>();
                    String nodeId = "dep-" + i;
                    depNode.put("id", nodeId);
                    depNode.put("name", depArtifactId);
                    depNode.put("version", depVersion);
                    depNode.put("groupId", depGroupId);
                    depNode.put("artifactId", depGroupId + ":" + depArtifactId);
                    depNode.put("type", "maven");
                    depNode.put("fullName", depGroupId + ":" + depArtifactId);
                    depNode.put("scope", depScope);
                    depNode.put("size", 10);
                    nodes.add(depNode);
                    
                    // 创建连接
                    Map<String, Object> link = new HashMap<>();
                    link.put("source", "project-root");
                    link.put("target", nodeId);
                    link.put("scope", depScope);
                    link.put("value", 1);
                    links.add(link);
                }
            }
            
            logger.info("创建了基本依赖图，包含 " + nodes.size() + " 个节点");
            
        } catch (Exception e) {
            logger.log(Level.WARNING, "解析POM创建基本依赖图时出错", e);
            
            // 创建一个最小化的依赖图
            Map<String, Object> rootNode = new HashMap<>();
            rootNode.put("id", "project-root");
            rootNode.put("name", pomFile.getParentFile().getName());
            rootNode.put("version", "unknown");
            rootNode.put("groupId", "unknown.group");
            rootNode.put("artifactId", "unknown:artifact");
            rootNode.put("type", "root");
            rootNode.put("fullName", "未知项目");
            rootNode.put("size", 15);
            nodes.add(rootNode);
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("nodes", nodes);
        result.put("links", links);
        return result;
    }
    
    /**
     * 从XML文档获取元素值
     */
    private String getXmlElementValue(Document doc, String tagName) {
        NodeList items = doc.getElementsByTagName(tagName);
        if (items.getLength() > 0) {
            return items.item(0).getTextContent();
        }
        return null;
    }
    
    /**
     * 从XML元素获取子元素值
     */
    private String getXmlSubElementValue(org.w3c.dom.Element element, String tagName) {
        NodeList items = element.getElementsByTagName(tagName);
        if (items.getLength() > 0) {
            return items.item(0).getTextContent();
        }
        return null;
    }
    
    /**
     * 检查POM文件是否包含依赖项
     */
    private boolean checkPomHasDependencies(File pomFile) {
        try {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pomFile);
            doc.getDocumentElement().normalize();
            NodeList dependencies = doc.getElementsByTagName("dependency");
            return dependencies.getLength() > 0;
        } catch (Exception e) {
            logger.log(Level.WARNING, "检查POM依赖时出错", e);
            return false;
        }
    }
    
    /**
     * 检查是否为有效的Maven项目结构
     */
    private boolean checkValidMavenStructure(String projectPath) {
        File srcFolder = new File(projectPath, "src/main/java");
        return srcFolder.exists() && srcFolder.isDirectory();
    }
    
    /**
     * 创建临时Maven项目结构用于分析依赖
     */
    private String createTemporaryMavenProject(File pomFile) throws Exception {
        String tempDir = System.getProperty("java.io.tmpdir");
        String projectDirName = "temp-maven-" + System.currentTimeMillis();
        File tempProject = new File(tempDir, projectDirName);
        if (!tempProject.mkdirs()) {
            throw new Exception("无法创建临时目录: " + tempProject.getAbsolutePath());
        }
        
        // 创建标准Maven目录结构
        new File(tempProject, "src/main/java").mkdirs();
        
        // 复制POM文件到临时目录
        Files.copy(pomFile.toPath(), new File(tempProject, "pom.xml").toPath());
        
        // 创建一个简单的Java类
        File srcPackageDir = new File(tempProject, "src/main/java/com/example");
        srcPackageDir.mkdirs();
        
        File mainJava = new File(srcPackageDir, "Main.java");
        try (FileOutputStream fos = new FileOutputStream(mainJava)) {
            String content = "package com.example;\n\npublic class Main {\n    public static void main(String[] args) {\n        System.out.println(\"Hello, World!\");\n    }\n}\n";
            fos.write(content.getBytes(StandardCharsets.UTF_8));
        }
        
        return tempProject.getAbsolutePath();
    }
    
    /**
     * 获取适合当前系统的Maven命令
     */
    private String getMavenCommand(String projectPath) {
        // 检查项目目录中是否有Maven Wrapper
        File mvnw = new File(projectPath, "mvnw");
        File mvnwCmd = new File(projectPath, "mvnw.cmd");
        
        logger.info("检查Maven Wrapper: mvnw存在=" + mvnw.exists() + ", mvnw.cmd存在=" + mvnwCmd.exists());
        
        // 在Windows上使用mvnw.cmd，在类Unix系统上使用mvnw
        if (isWindows()) {
            if (mvnwCmd.exists()) {
                logger.info("在Windows上使用Maven Wrapper: " + mvnwCmd.getAbsolutePath());
                // 确保使用绝对路径
                return mvnwCmd.getAbsolutePath();
            } else if (System.getenv("MAVEN_HOME") != null && new File(System.getenv("MAVEN_HOME"), "bin/mvn.cmd").exists()) {
                logger.info("使用MAVEN_HOME环境变量中的Maven");
                return new File(System.getenv("MAVEN_HOME"), "bin/mvn.cmd").getAbsolutePath();
            } else if (System.getenv("M2_HOME") != null && new File(System.getenv("M2_HOME"), "bin/mvn.cmd").exists()) {
                logger.info("使用M2_HOME环境变量中的Maven");
                return new File(System.getenv("M2_HOME"), "bin/mvn.cmd").getAbsolutePath();
            }
        } else {
            if (mvnw.exists()) {
                // 确保mvnw有执行权限
                mvnw.setExecutable(true);
                logger.info("在类Unix系统上使用Maven Wrapper: " + mvnw.getAbsolutePath());
                return mvnw.getAbsolutePath();
            } else if (System.getenv("MAVEN_HOME") != null && new File(System.getenv("MAVEN_HOME"), "bin/mvn").exists()) {
                logger.info("使用MAVEN_HOME环境变量中的Maven");
                return new File(System.getenv("MAVEN_HOME"), "bin/mvn").getAbsolutePath();
            } else if (System.getenv("M2_HOME") != null && new File(System.getenv("M2_HOME"), "bin/mvn").exists()) {
                logger.info("使用M2_HOME环境变量中的Maven");
                return new File(System.getenv("M2_HOME"), "bin/mvn").getAbsolutePath();
            }
        }
        
        // 回退到系统安装的Maven
        logger.info("使用系统PATH中的Maven");
        return isWindows() ? "mvn.cmd" : "mvn";
    }
    
    /**
     * 检测当前操作系统是否为Windows
     */
    private boolean isWindows() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("win");
    }
    
    private Map<String, String> parseDependencyLine(String line, List<Map<String, Object>> links, 
                                            Map<String, String> nodeIdMap, Map<String, Integer> dependencyCount) {
        // 提取源和目标依赖
        String[] parts = line.trim().split("->");
        if (parts.length == 2) {
            String source = parts[0].trim().replaceAll("\"", "");
            String target = parts[1].trim().replaceAll("\"", "").split("\\s+")[0].replaceAll("\"", "");
            
            // 创建唯一ID或使用已有的
            String sourceId = nodeIdMap.computeIfAbsent(source, k -> "mvn-" + nodeIdMap.size());
            String targetId = nodeIdMap.computeIfAbsent(target, k -> "mvn-" + nodeIdMap.size());
            
            // 记录依赖计数
            dependencyCount.put(target, dependencyCount.getOrDefault(target, 0) + 1);
            
            // 分析连接属性（例如依赖范围）
            String scopeMatch = extractScopeFromLine(line);
            String scope = (scopeMatch != null) ? scopeMatch : "compile";
            
            Map<String, Object> link = new HashMap<>();
            link.put("source", sourceId);
            link.put("target", targetId);
            link.put("scope", scope);
            link.put("value", 1); // 为可视化设置线宽
            links.add(link);
            
            Map<String, String> result = new HashMap<>();
            result.put("source", source);
            result.put("target", target);
            return result;
        }
        return null;
    }
    
    private String extractScopeFromLine(String line) {
        Pattern pattern = Pattern.compile("\\[label=\"([^\"]*?)\"");
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            String label = matcher.group(1);
            if (label.contains("scope=")) {
                String[] parts = label.split("scope=");
                if (parts.length > 1) {
                    return parts[1].trim().split("[,\\s]")[0];
                }
            }
        }
        return null;
    }
    
    private void parseNodeLine(String line, List<Map<String, Object>> nodes, Map<String, String> nodeIdMap) {
        // 提取节点信息
        String[] parts = line.trim().split("\\[label=");
        if (parts.length >= 2) {
            String nodeId = parts[0].trim().replaceAll("\"", "");
            String label = parts[1].split("\\]")[0].replaceAll("\"", "");
            
            // 解析标签中的名称和版本
            String name = label;
            String version = "";
            String groupId = "";
            
            if (nodeId.contains(":")) {
                String[] idParts = nodeId.split(":");
                if (idParts.length > 1) {
                    groupId = idParts[0];
                    name = idParts[1];
                }
            }
            
            if (label.contains("\\n")) {
                String[] labelParts = label.split("\\\\n");
                name = labelParts[0];
                version = labelParts.length > 1 ? labelParts[1] : "";
            }
            
            // 获取或创建唯一ID
            String uniqueId = nodeIdMap.computeIfAbsent(nodeId, k -> "mvn-" + nodeIdMap.size());
            
            Map<String, Object> node = new HashMap<>();
            node.put("id", uniqueId);
            node.put("name", name);
            node.put("version", version);
            node.put("groupId", groupId);
            node.put("artifactId", nodeId);
            node.put("type", "maven");
            node.put("fullName", groupId + ":" + name);
            nodes.add(node);
        }
    }
    
    /**
     * 获取更详细的依赖信息
     */
    private void enrichDependencyInfo(String projectPath, List<Map<String, Object>> nodes) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(getMavenCommand(projectPath), "dependency:list", "-DoutputFile=dependencies.txt");
            processBuilder.directory(new File(projectPath));
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                // 解析依赖列表文件
                File depFile = new File(projectPath, "dependencies.txt");
                if (depFile.exists()) {
                    try (BufferedReader reader = new BufferedReader(new java.io.FileReader(depFile))) {
                        String line;
                        Pattern depPattern = Pattern.compile("\\s+(\\S+):(\\S+):(\\S+):(\\S+):(\\S+)\\s*");
                        
                        while ((line = reader.readLine()) != null) {
                            Matcher matcher = depPattern.matcher(line);
                            if (matcher.find()) {
                                String groupId = matcher.group(1);
                                String artifactId = matcher.group(2);
                                String type = matcher.group(3);
                                String version = matcher.group(4);
                                String scope = matcher.group(5);
                                
                                // 更新节点信息
                                String fullArtifactId = groupId + ":" + artifactId;
                                for (Map<String, Object> node : nodes) {
                                    if (node.get("artifactId").equals(fullArtifactId)) {
                                        node.put("scope", scope);
                                        node.put("packaging", type);
                                        node.put("description", getArtifactDescription(groupId, artifactId, version));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    // 清理临时文件
                    depFile.delete();
                } else {
                    logger.warning("依赖列表文件未生成: " + depFile.getAbsolutePath());
                }
            } else {
                logger.warning("依赖列表命令执行失败: " + output.toString());
            }
        } catch (Exception e) {
            // 即使获取额外信息失败，也不应影响主要功能
            logger.warning("无法获取详细依赖信息: " + e.getMessage());
        }
    }
    
    /**
     * 获取构件描述（可以扩展为从Maven中央仓库获取）
     */
    private String getArtifactDescription(String groupId, String artifactId, String version) {
        // 这里可以实现从Maven仓库元数据获取描述的逻辑
        // 简单起见，返回一个基本描述
        return groupId + ":" + artifactId + " " + version;
    }
    
    /**
     * 递归删除目录及其内容
     * @param directory 要删除的目录
     * @return 删除是否成功
     */
    private boolean deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
        }
        return directory.delete();
    }
}