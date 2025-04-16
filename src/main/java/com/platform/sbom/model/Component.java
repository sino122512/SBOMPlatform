package com.platform.sbom.model;


import jakarta.persistence.*;

@Entity
public class Component {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 软件包名称
    private String name;
    // 版本
    private String version;
    // 组件类型，如 library、application 等
    private String type;
    // 可选：许可证信息
    private String license;
    // 可选：描述信息
    @Column(length = 1024)
    private String description;

    // getter 和 setter
    // ...（省略生成代码，可使用 IDE 自动生成）

    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getVersion() {
        return version;
    }
    public void setVersion(String version) {
        this.version = version;
    }
    public String getType() {
        return type;
    }
    public void setType(String type) {
        this.type = type;
    }
    public String getLicense() {
        return license;
    }
    public void setLicense(String license) {
        this.license = license;
    }
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }
}
