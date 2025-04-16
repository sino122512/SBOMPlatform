package com.platform.sbom.model;


import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
public class SBOM {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // SBOM 名称，比如项目名称
    private String name;

    // 生成时间
    private LocalDateTime generatedAt;

    // 存储 SBOM 格式（例如 CycloneDX 或 SPDX）
    private String format;

    // 组件列表，一个 SBOM 包含多个组件
    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinColumn(name = "sbom_id")
    private List<Component> components;

    // getter 和 setter

    public SBOM() {
        this.generatedAt = LocalDateTime.now();
    }

    // getters and setters
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
    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }
    public void setGeneratedAt(LocalDateTime generatedAt) {
        this.generatedAt = generatedAt;
    }
    public String getFormat() {
        return format;
    }
    public void setFormat(String format) {
        this.format = format;
    }
    public List<Component> getComponents() {
        return components;
    }
    public void setComponents(List<Component> components) {
        this.components = components;
    }
}
