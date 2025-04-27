package com.platform.sbom.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.platform.sbom.model.Component;
import com.platform.sbom.model.FileSystemInfo;
import com.platform.sbom.model.ImageInfo;
import com.platform.sbom.model.SourceInfo;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

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
     * Generate SBOM for a file system directory using Syft
     *
     * @param directory The directory to scan
     * @return List of components found
     */
    public List<Component> scanFileSystem(String directory) {
        return runSyftScan(directory, null);
    }

    /**
     * Generate SBOM for a container image using Syft
     *
     * @param imageName The image name to scan (e.g., alpine:latest)
     * @return List of components found
     */
    public List<Component> scanContainerImage(String imageName) {
        return runSyftScan(null, imageName);
    }

    /**
     * Generate SBOM from a container image tar file using Syft
     *
     * @param imageFile The tar file containing the container image
     * @return List of components found
     */
    public List<Component> scanContainerImageFromFile(File imageFile) {
        return runSyftScan("docker-archive:" + imageFile.getAbsolutePath(), null);
    }

    /**
     * Execute Syft and parse the output
     *
     * @param source     Directory path, docker-archive path, or null
     * @param imageName  Container image name or null
     * @return List of components found
     */
    private List<Component> runSyftScan(String source, String imageName) {
        List<Component> components = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            List<String> command = new ArrayList<>();
            command.add(syftPath);
            command.add("packages");

            // Set the source (directory, image, or archive)
            if (source != null) {
                command.add(source);
            } else if (imageName != null) {
                command.add(imageName);
            }

            // Output in JSON format
            command.add("-o");
            command.add("json");

            log.info("Running Syft command: {}", String.join(" ", command));
            pb.command(command);

            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                // Parse Syft JSON output
                components = parseSyftOutput(output.toString(), source, imageName);
            } else {
                log.error("Syft execution failed with exit code: {}", exitCode);
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                StringBuilder errorOutput = new StringBuilder();
                while ((line = errorReader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }
                log.error("Syft error: {}", errorOutput.toString());
            }
        } catch (Exception e) {
            log.error("Error executing Syft", e);
        }
        return components;
    }

    /**
     * Parse Syft JSON output into Component objects
     *
     * @param json       The JSON output from Syft
     * @param source     The source that was scanned
     * @param imageName  The image name that was scanned
     * @return List of components
     */
    private List<Component> parseSyftOutput(String json, String source, String imageName) {
        List<Component> components = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode artifacts = root.get("artifacts");

            if (artifacts != null && artifacts.isArray()) {
                for (JsonNode artifact : artifacts) {
                    Component component = new Component();

                    // Extract basic component info
                    component.setName(artifact.path("name").asText(""));
                    component.setVersion(artifact.path("version").asText(""));
                    component.setType(artifact.path("type").asText(""));

                    // Generate a unique SBOM reference
                    String sbomRef = "pkg:" + component.getType() + "/" + component.getName() + "@" + component.getVersion();
                    component.setSbomRef(sbomRef);

                    // Extract licenses
                    JsonNode licenses = artifact.path("licenses");
                    if (licenses != null && licenses.isArray() && licenses.size() > 0) {
                        component.setLicense(licenses.get(0).asText());
                    }

                    // Extract PURL if available
                    JsonNode purl = artifact.path("purl");
                    if (purl != null && !purl.isMissingNode()) {
                        component.setPurl(purl.asText());
                    }

                    // Extract CPE if available
                    JsonNode cpes = artifact.path("cpes");
                    if (cpes != null && cpes.isArray() && cpes.size() > 0) {
                        component.setCpe(cpes.get(0).asText());
                    }

                    // Set metadata based on source
                    if (imageName != null) {
                        component.setSourceRepo("container-image:" + imageName);
                    } else if (source != null) {
                        if (source.startsWith("docker-archive:")) {
                            component.setSourceRepo("container-image-archive");
                        } else {
                            component.setSourceRepo("filesystem:" + source);

                            // Extract file path if available
                            JsonNode locations = artifact.path("locations");
                            if (locations != null && locations.isArray() && locations.size() > 0) {
                                component.setFilePath(locations.get(0).path("path").asText());
                            }
                        }
                    }

                    components.add(component);
                }
            }
        } catch (Exception e) {
            log.error("Error parsing Syft output", e);
        }
        return components;
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
            ImageInfo imgInfo = new ImageInfo(imageName, "docker");
            sourceInfo.setImage(imgInfo);
        } else if (imageFile != null) {
            ImageInfo imgInfo = new ImageInfo(imageFile.getName(), "local-upload");
            sourceInfo.setImage(imgInfo);
        }

        return sourceInfo;
    }
}