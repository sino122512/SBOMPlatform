package com.platform.sbom.service;

import com.platform.sbom.model.Component;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class MavenPomParserService {

    /**
     * 扫描目录及其子目录下的所有pom.xml文件
     */
    public List<File> findPomFiles(String rootDir) throws IOException {
        return Files.walk(Paths.get(rootDir))
                .filter(path -> path.getFileName().toString().equals("pom.xml"))
                .map(Path::toFile)
                .collect(Collectors.toList());
    }

    /**
     * 解析单个pom.xml文件并提取依赖组件信息
     */
    public List<Component> parsePomFile(File pomFile) {
        List<Component> components = new ArrayList<>();
        Map<String, String> properties = new HashMap<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(pomFile);
            document.getDocumentElement().normalize();

            // 提取pom属性以便替换变量
            extractProperties(document, properties);

            // 提取当前项目信息
            String groupId = getElementValue(document, "groupId");
            String artifactId = getElementValue(document, "artifactId");
            String version = getElementValue(document, "version");

            // 提取依赖
            NodeList dependencies = document.getElementsByTagName("dependency");
            for (int i = 0; i < dependencies.getLength(); i++) {
                Element dependency = (Element) dependencies.item(i);
                Component component = extractComponent(dependency, properties);
                if (component != null) {
                    // 记录来源
                    component.setSourceRepo("pom.xml");
                    component.setFilePath(pomFile.getPath());
                    components.add(component);
                }
            }

        } catch (ParserConfigurationException | SAXException | IOException e) {
            System.err.println("Error parsing POM file: " + pomFile.getPath() + " - " + e.getMessage());
        }

        return components;
    }

    /**
     * 提取POM文件中的所有属性变量
     */
    private void extractProperties(Document document, Map<String, String> properties) {
        NodeList propertiesNodes = document.getElementsByTagName("properties");
        if (propertiesNodes.getLength() > 0) {
            Element propertiesElement = (Element) propertiesNodes.item(0);
            NodeList propertyList = propertiesElement.getChildNodes();

            for (int i = 0; i < propertyList.getLength(); i++) {
                if (propertyList.item(i) instanceof Element) {
                    Element property = (Element) propertyList.item(i);
                    String name = property.getNodeName();
                    String value = property.getTextContent().trim();
                    properties.put(name, value);
                }
            }
        }

        // 获取父POM的版本信息，可能在dependencyManagement中被引用
        NodeList parentNodes = document.getElementsByTagName("parent");
        if (parentNodes.getLength() > 0) {
            Element parent = (Element) parentNodes.item(0);
            String parentVersion = getElementTextContent(parent, "version");
            if (parentVersion != null && !parentVersion.isEmpty()) {
                properties.put("project.parent.version", parentVersion);
            }
        }
    }

    /**
     * 从依赖元素中提取组件信息
     */
    private Component extractComponent(Element dependency, Map<String, String> properties) {
        String groupId = getElementTextContent(dependency, "groupId");
        String artifactId = getElementTextContent(dependency, "artifactId");
        String version = getElementTextContent(dependency, "version");
        String scope = getElementTextContent(dependency, "scope");

        // 检查是否有必要的信息
        if (artifactId == null || artifactId.isEmpty()) {
            return null;
        }

        // 解析属性变量
        if (groupId != null && groupId.startsWith("${") && groupId.endsWith("}")) {
            String propName = groupId.substring(2, groupId.length() - 1);
            groupId = properties.getOrDefault(propName, groupId);
        }

        if (version != null && version.startsWith("${") && version.endsWith("}")) {
            String propName = version.substring(2, version.length() - 1);
            version = properties.getOrDefault(propName, version);
        }

        // 组装Component对象
        Component component = new Component();
        component.setName(artifactId);
        component.setType("library");

        if (groupId != null && !groupId.isEmpty()) {
            component.setVendor(groupId);
        }

        if (version != null && !version.isEmpty()) {
            component.setVersion(version);
        } else {
            component.setVersion("unknown");
        }

        // 设置sbomRef
        String ref = "pkg:maven/";
        ref += (groupId != null && !groupId.isEmpty()) ? groupId : "unknown";
        ref += "/" + artifactId;
        ref += "@" + component.getVersion();
        component.setSbomRef(ref);

        // 设置PURL
        component.setPurl(ref);

        // 设置范围信息
        if (scope != null && !scope.isEmpty()) {
            component.setDescription("Maven dependency with scope: " + scope);
        } else {
            component.setDescription("Maven dependency");
        }

        // 构造可能的主页URL
        component.setHomePage("https://search.maven.org/artifact/" +
                ((groupId != null && !groupId.isEmpty()) ? groupId : "unknown") +
                "/" + artifactId);

        return component;
    }

    /**
     * 从文档中获取指定标签的文本内容
     */
    private String getElementValue(Document doc, String tagName) {
        NodeList nodeList = doc.getElementsByTagName(tagName);
        if (nodeList.getLength() > 0) {
            return nodeList.item(0).getTextContent();
        }
        return null;
    }

    /**
     * 从元素中获取指定子标签的文本内容
     */
    private String getElementTextContent(Element element, String tagName) {
        NodeList nodeList = element.getElementsByTagName(tagName);
        if (nodeList.getLength() > 0) {
            return nodeList.item(0).getTextContent();
        }
        return null;
    }
}
