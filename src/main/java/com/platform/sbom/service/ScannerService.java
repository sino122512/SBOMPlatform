package com.platform.sbom.service;

import com.platform.sbom.model.Component;
import org.apache.commons.compress.archivers.tar.*;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.*;

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
                        if (c != null) list.add(c);
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
            return c;
        }
        return null;
    }

    private void deleteRec(Path p) throws IOException {
        Files.walk(p).sorted((a,b)->b.compareTo(a))
                .forEach(q->q.toFile().delete());
    }
}
