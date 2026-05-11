# M14 / E4-A 联合采集总体设计文档

## 1. 目标

本阶段目标是将三地 Routinator VRP 自动采集与同窗 Object Layer 采集合并为统一 joint snapshot group，解决当前 E4-A 阻塞项：

`same_window_object_layer_context_missing`

## 2. 当前范围

当前只做：

- E4-A：跨地域同 Validator 输出差异
- 三地 Routinator VRP 输出差异
- VRP snapshot 与 Object snapshot 联合采集
- Collector joint grouping
- Object layer compare
- E4-A joint final verdict

当前不做：

- 不安装 rpki-client
- 不安装 FORT
- 不做 E4-B cross-validator
- 不加载 BGP RIB
- 不计算 ROV state change
- 不做控制面影响真实评估

仅预留：

- e4b_cross_validator = reserved_only
- control_plane_impact = reserved_only

## 3. 联合采集链路

Probe 侧：

1. VRP snapshot export
2. Object snapshot export
3. Joint snapshot manifest build
4. Upload to Collector

Collector 侧：

1. 接收 VRP snapshot
2. 接收 Object snapshot
3. 生成 joint snapshot group
4. 判断 vrp_group_complete
5. 判断 object_group_complete
6. 运行 VRP lowmem diff
7. 运行 Object layer compare
8. 生成 E4-A joint final verdict
9. 打包 evidence pack

## 4. 核心数据

### VRP Snapshot

- probe_id
- validator_name
- validator_version
- generatedTime
- vrp_count
- unique_vrp_count
- vrp_root_v1
- vrp_digest
- gzip_path
- sha256_gzip

### Object Snapshot

- probe_id
- object_set_root
- effective_object_root
- active_manifest_count
- object_inventory_count
- active_manifest_records_path
- object_inventory_path
- manifest_parse_error_count
- expired_manifest_count
- fetch_completeness

### Joint Snapshot Group

- snapshot_group_id
- received_vrp_probes
- received_object_probes
- vrp_group_complete
- object_group_complete
- joint_group_complete
- generated_time_skew_seconds
- window_mapping_level

## 5. 目标状态

联合采集完成后，最终 verdict 应从：

`blocked_object_layer_unverified`

推进到以下之一：

1. `not_e4_object_layer_version_skew`
2. `e4a_candidate_cross_region_same_validator`
3. 若仍缺上下文，则保持 `blocked_object_layer_unverified`

## 6. 安全原则

- 不复用历史对象层 verdict 作为同窗证据
- 必须存在 object_set_root 或 effective_object_root
- 必须存在 active_manifest_records 或等价对象层记录
- 不上传 raw RPKI objects
- 新接口优先使用 sidecar，避免影响现有 Collector 主服务
