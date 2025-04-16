package com.platform.sbom.service;

import com.platform.sbom.model.Component;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Service
public class ScannerService {

    /**
     * 扫描文件系统目录，递归查找 .jar 文件，生成组件列表
     */
    public List<Component> scanFileSystem(String pathStr) {
        List<Component> components = new ArrayList<>();
        Path startPath = Paths.get(pathStr);
        try {
            Files.walk(startPath)
                    .filter(p -> p.toString().toLowerCase().endsWith(".jar"))
                    .forEach(jarPath -> {
                        Component comp = parseJarFile(jarPath);
                        if (comp != null) {
                            components.add(comp);
                        }
                    });
        } catch (IOException e) {
            e.printStackTrace();
        }
        return components;
    }

    /**
     * 扫描容器镜像：调用 docker save 命令获取镜像 tar 包，解压后扫描其中 jar 文件
     */
    public List<Component> scanContainerImage(String imageName) {
        List<Component> components = new ArrayList<>();
        Path tempTar = null;
        try {
            // 创建临时文件保存 docker 镜像 tar 包
            tempTar = Files.createTempFile("docker-image", ".tar");
            // 调用 docker save 命令：需要确保 Docker 已安装并配置正确
            ProcessBuilder pb = new ProcessBuilder("docker", "save", "-o", tempTar.toString(), imageName);
            Process process = pb.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                System.err.println("docker save 命令执行失败，退出码：" + exitCode);
                return components;
            }
            // 创建临时目录用于解压 tar 包
            Path tempDir = Files.createTempDirectory("docker-image-extract");
            extractTar(tempTar.toFile(), tempDir.toFile());
            // 扫描解压目录中的 jar 文件
            components.addAll(scanFileSystem(tempDir.toString()));
            // 删除临时目录
            deleteDirectoryRecursively(tempDir);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } finally {
            if (tempTar != null) {
                try {
                    Files.deleteIfExists(tempTar);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return components;
    }

    /**
     * 解析 jar 文件，示例中简单从文件名中提取组件名称和版本信息
     */
    private Component parseJarFile(Path jarPath) {
        String fileName = jarPath.getFileName().toString();
        if (!fileName.toLowerCase().endsWith(".jar")) {
            return null;
        }
        // 去掉 .jar 后缀
        String baseName = fileName.substring(0, fileName.length() - 4);
        // 假设文件名格式为 "name-version.jar" ，以 "-" 分割
        String[] parts = baseName.split("-");
        if (parts.length < 2) {
            return null;
        }
        // 取最后一部分作为版本，其余部分合并为名称
        String version = parts[parts.length - 1];
        String name = String.join("-", java.util.Arrays.copyOf(parts, parts.length - 1));
        Component comp = new Component();
        comp.setName(name);
        comp.setVersion(version);
        comp.setType("library");
        comp.setLicense("UNKNOWN");
        comp.setDescription("从 " + jarPath.toString() + " 解析的组件");
        return comp;
    }

    /**
     * 解压 tar 文件到指定目录
     */
    private void extractTar(File tarFile, File destDir) throws IOException {
        try (FileInputStream fis = new FileInputStream(tarFile);
             BufferedInputStream bis = new BufferedInputStream(fis);
             TarArchiveInputStream tais = new TarArchiveInputStream(bis)) {
            TarArchiveEntry entry;
            while ((entry = tais.getNextTarEntry()) != null) {
                File curFile = new File(destDir, entry.getName());
                if (entry.isDirectory()) {
                    curFile.mkdirs();
                } else {
                    File parent = curFile.getParentFile();
                    if (!parent.exists()) {
                        parent.mkdirs();
                    }
                    try (OutputStream out = new FileOutputStream(curFile)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = tais.read(buffer)) != -1) {
                            out.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }

    /**
     * 递归删除目录
     */
    private void deleteDirectoryRecursively(Path path) throws IOException {
        Files.walk(path)
                .sorted((a, b) -> b.compareTo(a))
                .forEach(p -> {
                    try {
                        Files.delete(p);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
    }
}