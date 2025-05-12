package com.platform.sbom.controller;

import com.platform.sbom.model.Component;
import com.platform.sbom.model.Dependency;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.service.SBOMService;
import com.platform.sbom.service.MavenDependencyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 组件依赖图控制器
 */
@Controller
@RequestMapping("/dependency-graph")
public class DependencyGraphController {

    @Autowired
    private SBOMService sbomService;
    
    @Autowired
    private MavenDependencyService mavenDependencyService;

    
    
    /**
     * 展示Maven依赖图页面
     * @return 视图名称
     */
    @GetMapping("/maven")
    public String showMavenDependencyGraph(Model model) {
        return "maven-dependency-graph";
    }
    
    /**
     * 获取Maven依赖图数据
     * @param projectPath Maven项目路径
     * @return Maven依赖图数据
     */
    @GetMapping("/maven/data")
    @ResponseBody
    public ResponseEntity<?> getMavenDependencyGraphData(@RequestParam String projectPath) {
        try {
            Map<String, Object> dependencyData = mavenDependencyService.analyzeMavenDependencies(projectPath);
            return ResponseEntity.ok(dependencyData);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "解析Maven依赖失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
    
    /**
     * 上传pom.xml文件分析依赖
     * @return 依赖图数据
     */
    @PostMapping("/maven/upload")
    @ResponseBody
    public ResponseEntity<?> uploadPomFile(@RequestParam("file") org.springframework.web.multipart.MultipartFile file) {
        File dir = null;
        try {
            // 验证上传的是pom文件
            if (!file.getOriginalFilename().endsWith(".xml") && !file.getOriginalFilename().equals("pom.xml")) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "请上传有效的pom.xml文件");
                return ResponseEntity.badRequest().body(error);
            }
            
            // 保存上传的pom文件到临时目录
            String tempDir = System.getProperty("java.io.tmpdir");
            String projectDirName = "maven-analysis-" + System.currentTimeMillis();
            dir = new File(tempDir, projectDirName);
            if (!dir.exists() && !dir.mkdirs()) {
                throw new Exception("无法创建临时目录: " + dir.getAbsolutePath());
            }
            
            // 创建pom文件
            File pomFile = new File(dir, "pom.xml");
            file.transferTo(pomFile);
            
            // 分析依赖
            Map<String, Object> dependencyData = mavenDependencyService.analyzeMavenDependencies(dir.getAbsolutePath());
            
            return ResponseEntity.ok(dependencyData);
        } catch (Exception e) {
            // 记录详细错误信息
            e.printStackTrace();
            Map<String, String> error = new HashMap<>();
            error.put("error", "解析Maven依赖失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        } finally {
            // 在finally块中清理临时目录，确保在分析完成后才删除
            if (dir != null && dir.exists()) {
                deleteDirectory(dir);
            }
        }
    }
    
    /**
     * 递归删除目录及其内容
     * @param directory 要删除的目录
     * @return 删除是否成功
     */
    private boolean deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
        }
        return directory.delete();
    }
}