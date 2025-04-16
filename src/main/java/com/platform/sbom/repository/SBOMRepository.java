package com.platform.sbom.repository;

import com.platform.sbom.model.SBOM;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

//数据存储层
@Repository
public interface SBOMRepository extends JpaRepository<SBOM, Long> {
    // 可根据需要添加自定义查询方法
}