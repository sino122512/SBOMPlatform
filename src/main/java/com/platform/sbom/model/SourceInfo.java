package com.platform.sbom.model;

public class SourceInfo {
    private FileSystemInfo filesystem;
    private ImageInfo image;

    public SourceInfo() {

    }

    // getters/setters…

    public FileSystemInfo getFilesystem() {
        return filesystem;
    }

    public void setFilesystem(FileSystemInfo filesystem) {
        this.filesystem = filesystem;
    }

    public ImageInfo getImage() {
        return image;
    }

    public void setImage(ImageInfo image) {
        this.image = image;
    }
}

