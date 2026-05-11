# M14 / E4-A 联合采集执行计划概述

## 总体路线

P0：联合采集设计与配置落地  
P1：成都节点 object snapshot export 单点试跑  
P2：成都节点 joint snapshot manifest 单点试跑  
P3：北京、新加坡复制并试跑 object snapshot export  
P4：Collector object upload sidecar 开发与启动  
P5：三地 object snapshot 上传与 joint grouping  
P6：Collector object layer compare  
P7：E4-A joint final verdict  
P8：联合 evidence pack 与归档  

## 当前 P0 范围

P0 只做设计、配置和计划落地。

不做：

- 不改服务
- 不重启 Collector
- 不重启 Probe
- 不操作北京和新加坡
- 不安装新 validator
- 不加载 BGP 数据

## P0 后的下一步

P1 将只在成都节点开发和试跑：

`scripts/p3/probe_export_object_snapshot_once.py`

目标是先本地生成 object_snapshot_record.json 和 object_snapshot.tar.gz。
