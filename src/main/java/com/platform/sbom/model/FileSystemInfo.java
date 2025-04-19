package com.platform.sbom.model;

public class FileSystemInfo {
    private String path;
    private boolean recursive;
    // constructors, getters/setters…

    public FileSystemInfo(String path, boolean recursive) {
        this.path = path;
        this.recursive = recursive;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public boolean isRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }
}
