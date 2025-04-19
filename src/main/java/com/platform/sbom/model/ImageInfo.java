package com.platform.sbom.model;

public class ImageInfo {
    private String imageId;
    private String registry;
    // constructors, getters/setters…

    public ImageInfo(String imageId, String registry) {
        this.imageId = imageId;
        this.registry = registry;
    }

    public String getImageId() {
        return imageId;
    }

    public void setImageId(String imageId) {
        this.imageId = imageId;
    }

    public String getRegistry() {
        return registry;
    }

    public void setRegistry(String registry) {
        this.registry = registry;
    }
}
