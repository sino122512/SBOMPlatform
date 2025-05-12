package com.platform.sbom.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 首页控制器，处理根路径请求
 */
@Controller
public class IndexController {

    /**
     * 处理根路径请求，重定向到首页
     */
    @GetMapping("/")
    public String index() {
        return "index";
    }
    
    /**
     * 为"/dependency-graph"路径提供重定向到Maven依赖图页面
     */
    @GetMapping("/dependency-graph")
    public String dependencyGraph() {
        return "redirect:/dependency-graph/maven";
    }
    
    /**
     * 处理通用错误页面请求
     */
    @GetMapping("/error")
    public String error() {
        return "error";
    }
}