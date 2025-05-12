package com.platform.sbom.controller;

import com.platform.sbom.model.Component;
import com.platform.sbom.model.Dependency;
import com.platform.sbom.model.SBOM;
import com.platform.sbom.service.SBOMService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

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

    /**
     * 展示组件依赖图页面
     * @return 视图名称
     */
    @GetMapping
    public String showDependencyGraphList(Model model) {
        model.addAttribute("sboms", sbomService.getAllSBOMs());
        return "dependency-graph-list";
    }
    
    /**
     * 展示特定SBOM的依赖图
     * @param id SBOM的ID
     * @return 视图名称
     */
    @GetMapping("/{id}")
    public String showDependencyGraph(@PathVariable Long id, Model model) {
        Optional<SBOM> sbomOpt = sbomService.getSBOMById(id);
        if (sbomOpt.isPresent()) {
            model.addAttribute("sbom", sbomOpt.get());
            return "dependency-graph";
        }
        return "redirect:/dependency-graph";
    }
    
    /**
     * 获取依赖图数据
     * @param id SBOM的ID
     * @return 依赖图数据
     */
    @GetMapping("/{id}/data")
    @ResponseBody
    public ResponseEntity<?> getDependencyGraphData(@PathVariable Long id) {
        Optional<SBOM> sbomOpt = sbomService.getSBOMById(id);
        if (sbomOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        SBOM sbom = sbomOpt.get();
        Map<String, Object> result = new HashMap<>();
        
        // 节点数据
        List<Map<String, Object>> nodes = new ArrayList<>();
        
        // 组件映射表，用于确保每个组件只添加一次
        Map<String, Map<String, Object>> componentMap = new HashMap<>();
        
        // 首先添加所有组件
        for (Component component : sbom.getComponents()) {
            String nodeId = component.getSbomRef();
            if (nodeId == null || nodeId.isEmpty()) {
                nodeId = "comp-" + component.getId();
            }
            
            Map<String, Object> node = new HashMap<>();
            node.put("id", nodeId);
            node.put("name", component.getName());
            node.put("version", component.getVersion());
            node.put("type", component.getType());
            node.put("license", component.getLicense());
            node.put("purl", component.getPurl());
            
            componentMap.put(nodeId, node);
        }
        
        // 边数据
        List<Map<String, Object>> links = new ArrayList<>();
        
        // 默认添加一个"system"节点作为根节点
        Map<String, Object> systemNode = new HashMap<>();
        systemNode.put("id", "system");
        systemNode.put("name", "系统");
        systemNode.put("type", "root");
        componentMap.put("system", systemNode);
        
        // 处理依赖关系
        if (sbom.getDependencies() != null && !sbom.getDependencies().isEmpty()) {
            for (Dependency dependency : sbom.getDependencies()) {
                String source = dependency.getRef();
                // 确保source节点存在
                if (!componentMap.containsKey(source)) {
                    Map<String, Object> sourceNode = new HashMap<>();
                    sourceNode.put("id", source);
                    sourceNode.put("name", source);
                    sourceNode.put("type", "unknown");
                    componentMap.put(source, sourceNode);
                }
                
                if (dependency.getDependsOn() != null) {
                    for (String target : dependency.getDependsOn()) {
                        // 确保target节点存在
                        if (!componentMap.containsKey(target)) {
                            continue; // 跳过不存在的目标节点
                        }
                        
                        Map<String, Object> link = new HashMap<>();
                        link.put("source", source);
                        link.put("target", target);
                        links.add(link);
                    }
                }
            }
        } else {
            // 如果没有依赖关系数据，创建简单的放射状布局
            // 系统节点连接到所有组件
            for (String compId : componentMap.keySet()) {
                if (!"system".equals(compId)) {
                    Map<String, Object> link = new HashMap<>();
                    link.put("source", "system");
                    link.put("target", compId);
                    links.add(link);
                }
            }
        }
        
        // 将组件映射表转换为节点列表
        nodes.addAll(componentMap.values());
        
        result.put("nodes", nodes);
        result.put("links", links);
        
        return ResponseEntity.ok(result);
    }
} 