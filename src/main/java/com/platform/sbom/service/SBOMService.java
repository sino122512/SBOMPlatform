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
    private final MavenPomParserService mavenPomParser;

    public SBOMService(SBOMRepository repo, SBOMDocumentRepository docRepo, SyftService syftService,
                       SBOMConverter converter, JdbcTemplate jdbcTemplate,
                       MavenPomParserService mavenPomParser) {
        this.repo = repo;
        this.docRepo = docRepo;
        this.syftService = syftService;
        this.converter = converter;
        this.jdbcTemplate = jdbcTemplate;
        this.mavenPomParser = mavenPomParser;
    }

    public boolean existsById(Long id) {
        return repo.existsById(id);
    }

    public List<SBOM> listAll() {
        return repo.findAll();
    }

    public Optional<SBOM> find(Long id) {
        return repo.findById(id);
    }

    /**
     * Generate SBOM using Syft for system files
     */
    @Transactional
    public SBOM generate(String name, MultipartFile[] folder, MultipartFile img) throws Exception {
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

        // Use Syft to scan the directory
        List<Component> syftComponents = syftService.scanFileSystem(tmpF.getAbsolutePath());
        log.info("Syft found {} components", syftComponents.size());

        // Also use POM parser to get more detailed Maven metadata
//        List<Component> pomComponents = new ArrayList<>();
//        List<File> pomFiles = mavenPomParser.findPomFiles(tmpF.getAbsolutePath());
//        for (File pomFile : pomFiles) {
//            pomComponents.addAll(mavenPomParser.parsePomFile(pomFile));
//        }
//        log.info("POM parser found {} components", pomComponents.size());

        // Merge components, preferring POM metadata where available
        Map<String, Component> uniqueComponents = new HashMap<>();

        // First add Syft components
        for (Component comp : syftComponents) {
            uniqueComponents.put(comp.getSbomRef(), comp);
        }

        // Then add/update with POM components which might have better metadata
//        for (Component comp : pomComponents) {
//            Component existing = uniqueComponents.get(comp.getSbomRef());
//            if (existing != null) {
//                // Update existing component with more detailed POM metadata
//                if (existing.getLicense() == null) existing.setLicense(comp.getLicense());
//                if (existing.getVendor() == null) existing.setVendor(comp.getVendor());
//                if (existing.getHomePage() == null) existing.setHomePage(comp.getHomePage());
//                if (existing.getSourceRepo() == null) existing.setSourceRepo(comp.getSourceRepo());
//            } else {
//                uniqueComponents.put(comp.getSbomRef(), comp);
//            }
//        }

        // Replace temporary paths with original paths
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

        // Enhance metadata
        List<Component> finalComponents = new ArrayList<>(uniqueComponents.values());
        enhanceLicenseInfo(finalComponents);
        enrichMavenMetadata(finalComponents);

        // Handle container image if provided
        if (img != null && !img.isEmpty()) {
            File tmpI = File.createTempFile("img", ".tar");
            img.transferTo(tmpI);

            // Use Syft to scan the container image
            List<Component> imageComps = syftService.scanContainerImageFromFile(tmpI);
            log.info("Syft found {} components in container image", imageComps.size());

            for (Component comp : imageComps) {
                comp.setSourceRepo("container-image");
                if (comp.getDescription() == null) {
                    comp.setDescription("From container image");
                }
            }

            finalComponents.addAll(imageComps);
            tmpI.delete();
        }

        // Build dependencies
        List<Dependency> deps = buildDependencies(finalComponents);

        // Create source info based on scanned sources
        SourceInfo sourceInfo = new SourceInfo();
        FileSystemInfo fsInfo = new FileSystemInfo(tmpF.getAbsolutePath(), true);
        sourceInfo.setFilesystem(fsInfo);

        if (img != null && !img.isEmpty()) {
            ImageInfo imgInfo = new ImageInfo(img.getOriginalFilename(), "local-upload");
            sourceInfo.setImage(imgInfo);
        }

        // Build SBOM object
        SBOM sb = new SBOM();
        // Set ID manually
        Long maxId = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);
        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        sb.setToolName("SBOMPlatform-Syft");
        sb.setToolVersion("1.0.0");
        sb.setComponents(finalComponents);
        sb.setDependencies(deps);
        sb.setSource(sourceInfo);

        // Save to database
        SBOM saved = repo.save(sb);
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));

        return saved;
    }

    /**
     * Generate SBOM directly for a container image
     */
    @Transactional
    public SBOM generateForContainerImage(String name, String imageName) throws Exception {
        // Use Syft to scan the container image
        List<Component> components = syftService.scanContainerImage(imageName);
        log.info("Syft found {} components in container image {}", components.size(), imageName);

        // Enhance metadata
        enhanceLicenseInfo(components);

        // Build dependencies
        List<Dependency> deps = buildDependencies(components);

        // Create source info
        SourceInfo sourceInfo = syftService.createSourceInfo(null, imageName, null);

        // Build SBOM object
        SBOM sb = new SBOM();
        // Set ID manually
        Long maxId = jdbcTemplate.queryForObject("SELECT COALESCE(MAX(id), 0) FROM sbom", Long.class);
        sb.setId(maxId + 1);
        sb.setName(name);
        sb.setNamespace("urn:sbom:" + UUID.randomUUID());
        sb.setToolName("SBOMPlatform-Syft");
        sb.setToolVersion("1.0.0");
        sb.setComponents(components);
        sb.setDependencies(deps);
        sb.setSource(sourceInfo);

        // Save to database
        SBOM saved = repo.save(sb);
        String json = converter.toCustomJson(saved);
        docRepo.save(new SBOMDocument(saved.getId(), json));

        return saved;
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

    // Enhance license information
    private void enhanceLicenseInfo(List<Component> components) {
        for (Component comp : components) {
            if (comp.getLicense() == null) {
                // Common open source licenses
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

    // Build dependency relationships
    private List<Dependency> buildDependencies(List<Component> components) {
        // Create a simple dependency graph
        List<Dependency> dependencies = new ArrayList<>();

        // Create a root system component
        if (!components.isEmpty()) {
            Dependency rootDep = new Dependency();
            rootDep.setRef("system");

            // All direct dependencies
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