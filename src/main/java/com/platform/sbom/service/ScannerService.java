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
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ScannerService {
    public List<Component> scanFileSystem(String rootDir) {
        List<Component> list = new ArrayList<>();
        try {
            Files.walk(Paths.get(rootDir))
                    .filter(p -> p.toString().endsWith(".jar"))
                    .forEach(p -> {
                        Component c = parseJarManifest(p.toFile());
                        if (c == null) c = parseJarFilename(p.getFileName().toString());
                        if (c != null) {
                            // 记录文件路径
                            c.setFilePath(p.toString());
                            list.add(c);
                        }
                    });
        } catch (IOException ignored) {}
        return list;
    }

    public List<Component> scanContainerImageFromFile(File tar) {
        List<Component> list = new ArrayList<>();
        try {
            Path tmp = Files.createTempDirectory("img");
            try (TarArchiveInputStream tais = new TarArchiveInputStream(
                    new BufferedInputStream(new FileInputStream(tar)))) {
                TarArchiveEntry e;
                while ((e = tais.getNextTarEntry()) != null) {
                    File f = new File(tmp.toFile(), e.getName());
                    if (e.isDirectory()) f.mkdirs();
                    else {
                        f.getParentFile().mkdirs();
                        try (OutputStream os = new FileOutputStream(f)) {
                            byte[] buf = new byte[4096]; int r;
                            while ((r = tais.read(buf)) != -1) os.write(buf,0,r);
                        }
                    }
                }
            }
            list.addAll(scanFileSystem(tmp.toString()));
            // 对容器镜像中发现的组件进行标记
            list.forEach(c -> {
                if (c.getSourceRepo() == null) {
                    c.setSourceRepo("container-image");
                }
            });
            deleteRec(tmp);
        } catch (IOException ignored) {}
        return list;
    }

    private Component parseJarManifest(File jar) {
        try (JarFile jf = new JarFile(jar)) {
            Manifest m = jf.getManifest();
            if (m != null) {
                String t = m.getMainAttributes().getValue("Implementation-Title"),
                        v = m.getMainAttributes().getValue("Implementation-Version");
                if (t != null && v != null) {
                    Component c = new Component();
                    c.setSbomRef("pkg:" + t + "@" + v);
                    c.setName(t);
                    c.setVersion(v);
                    c.setType("library");
                    c.setDescription("From MANIFEST");

                    // 增强的元数据收集
                    c.setLicense(m.getMainAttributes().getValue("Implementation-License"));
                    c.setVendor(m.getMainAttributes().getValue("Implementation-Vendor"));
                    c.setHomePage(m.getMainAttributes().getValue("Implementation-URL"));
                    c.setSourceRepo(extractSourceRepo(m));

                    // 尝试构建 purl
                    if (c.getPurl() == null && t != null && v != null) {
                        c.setPurl("pkg:maven/" + normalizePackageName(t) + "/" + normalizePackageName(t) + "@" + v);
                    }

                    return c;
                }
            }
        } catch (IOException ignored){}
        return null;
    }

    private Component parseJarFilename(String filename) {
        String name = filename.replaceAll("\\.jar$", "");
        int idx = name.lastIndexOf('-');
        if (idx > 0) {
            Component c = new Component();
            c.setSbomRef("pkg:" + name);
            c.setName(name.substring(0, idx));
            c.setVersion(name.substring(idx+1));
            c.setType("library");
            c.setDescription("From filename");

            // 尝试检测 Maven 坐标
            Pattern p = Pattern.compile("(.+)-([0-9].+)");
            Matcher m = p.matcher(name);
            if (m.matches()) {
                String artifactId = m.group(1);
                String version = m.group(2);
                // 尝试从文件名猜测 groupId
                String groupId = guessGroupId(artifactId);
                c.setPurl("pkg:maven/" + groupId + "/" + artifactId + "@" + version);
            }

            return c;
        }
        return null;
    }

    // 从 MANIFEST 中提取源代码库信息
    private String extractSourceRepo(Manifest manifest) {
        String scm = manifest.getMainAttributes().getValue("SCM-URL");
        if (scm != null) return scm;

        String url = manifest.getMainAttributes().getValue("Implementation-URL");
        if (url != null && (url.contains("github.com") || url.contains("gitlab") || url.contains("bitbucket"))) {
            return url;
        }

        return null;
    }

    // normalize package name for purl
    private String normalizePackageName(String name) {
        return name.toLowerCase().replace(" ", "-");
    }

    // 基于常见命名约定猜测 groupId
    private String guessGroupId(String artifactId) {
        // 默认使用 artifactId 作为 groupId
        return artifactId;
    }

    private void deleteRec(Path p) throws IOException {
        Files.walk(p).sorted((a,b)->b.compareTo(a))
                .forEach(q->q.toFile().delete());
    }
}
