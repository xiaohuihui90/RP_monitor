# M14 / E4-A 联合采集软件开发设计文档

## 1. 新增软件模块

### Probe 侧

1. `scripts/p3/probe_export_object_snapshot_once.py`

功能：生成 object snapshot。

输出：

- object_snapshot_record.json
- active_manifest_records.jsonl
- object_inventory.jsonl
- object_snapshot.tar.gz
- sha256.txt
- P1_object_export_acceptance_check.txt

2. `scripts/p3/probe_build_joint_snapshot_manifest.py`

功能：合并 VRP snapshot 与 Object snapshot。

输出：

- joint_snapshot_manifest.json
- sha256.txt
- P2_joint_manifest_acceptance_check.txt

3. `scripts/p3/probe_upload_object_snapshot.py`

功能：上传 object snapshot 到 Collector object upload sidecar。

接口：

- POST /api/v1/e4a/object/upload

### Collector 侧

1. `scripts/p3/run_e4a_object_upload_sidecar.py`

功能：提供 object snapshot upload API。

端口：

- 28115

接口：

- GET /api/v1/health
- POST /api/v1/e4a/object/upload

2. `scripts/p3/update_e4a_joint_group_manifest.py`

功能：合并 VRP group 与 Object group，生成 joint_group_manifest.json。

3. `scripts/p3/run_e4a_object_layer_compare.py`

功能：对三地 object snapshot 做对象层比较。

输出：

- object_layer_verdict.json
- object_layer_compare_acceptance_check.txt

4. `scripts/p3/run_e4a_joint_final_verdict.py`

功能：合并 VRP diff、object layer verdict、validator context、window context、fetch context、infra placeholder，输出 E4-A joint final verdict。

5. `scripts/p3/package_e4a_joint_evidence_pack.py`

功能：打包联合 evidence pack。

## 2. 开发批次

P0：设计与配置落地  
P1：成都 object snapshot export 试跑  
P2：成都 joint snapshot manifest 试跑  
P3：北京、新加坡 object snapshot export 试跑  
P4：Collector object upload sidecar  
P5：三地 object upload 与 joint grouping  
P6：Object layer compare  
P7：E4-A joint final verdict  
P8：联合 evidence pack 与归档  

## 3. 当前阶段限制

- 不安装新 validator
- 不加载 BGP 数据
- 不做 E4-B 真实开发
- 不做控制面影响真实评估
- 仅预留相关字段和状态

## 4. 最终完成标准

- vrp_group_complete = True
- object_group_complete = True
- joint_group_complete = True
- object_layer_verdict_exists = True
- final_verdict_e4a_joint_exists = True
- e4a_joint_evidence_pack_exists = True
