# S3 阶段性汇报快照

- generated_at_utc: 2026-05-11T09:30:14.661863+00:00
- report_id: s3_stage_report_20260511T093014Z
- key_group_id: group_m15_20260510T165500Z

## 1. M15 / P11 三层闭环最终结果

- final_status: `not_e4_object_layer_divergence_under_aligned_l1`
- e4_status: `blocked`
- confirmed_allowed: `False`
- blocking_layer: `object_layer`
- attribution_layer: `object_view`
- confidence: `high`

## 2. 三层视图结果

| Layer | complete | strong/window | aligned | skew_seconds | key_diff |
|---|---:|---:|---:|---:|---:|
| L1 announced | True | strong | True | 17 | None |
| L2 object | True | strong | False | 16 | inventory=625502, active=624826 |
| L3 VRP | True | strong | False | 21 | 5154760 |

## 3. L1 PP 级摘要

| PP | strict_aligned | serial_by_probe | notification_digest_aligned | snapshot_hash_aligned |
|---|---:|---|---:|---:|
| arin | True | {'probe-cd': 119446, 'probe-bj': 119446, 'probe-sg': 119446} | True | True |
| ripe | True | {'probe-cd': 198205, 'probe-bj': 198205, 'probe-sg': 198205} | True | True |
| apnic | True | {'probe-cd': 46825, 'probe-bj': 46825, 'probe-sg': 46825} | True | True |

## 4. 工程 closeout

- M15_closeout_acceptance: `True`
- closeout_id: `m15_p11_three_layer_closeout_group_m15_20260510T165500Z_20260511T031244Z`
- closeout_dir: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_closeout/m15_p11_three_layer_closeout_group_m15_20260510T165500Z_20260511T031244Z`

## 5. 重要说明

- 当前系统已完成 strict 三层联合归因闭环工程收口。
- 当前完整 M15/P11 三层归因流程仍是人工触发批处理；尚未做成周期性全自动流水线。
- VRP pairwise diff 数值在论文使用前建议以 canonical key 口径复核。
- object_source_mode 当前仍以 cache/object inventory 为基础，需要作为工程限制说明。

## 6. 输入证据文件路径

- m15_closeout_manifest: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_closeout/m15_p11_three_layer_closeout_group_m15_20260510T165500Z_20260511T031244Z/manifests/M15_P11_three_layer_closeout_manifest.json`
- m15_closeout_acceptance: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_closeout/m15_p11_three_layer_closeout_group_m15_20260510T165500Z_20260511T031244Z/checks/M15_P11_three_layer_closeout_acceptance.txt`
- m15_three_layer_verdict: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_strict/m15_strict_three_layer_gate_group_m15_20260510T165500Z_20260511T023241Z/verdicts/three_layer_final_verdict.json`
- m15_l1_manifest: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_l1/m15_l1_announced_view_group_group_m15_20260510T165500Z_20260511T022201Z/outputs/announced_view_group_manifest.json`
- m15_object_verdict: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_strict/m15_strict_three_layer_gate_group_m15_20260510T165500Z_20260511T023241Z/verdicts/object_layer_verdict.json`
- m15_vrp_summary: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_strict/m15_strict_three_layer_gate_group_m15_20260510T165500Z_20260511T023241Z/outputs/m14_vrp_summary.json`
- m15_vrp_diff: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_strict/m15_strict_three_layer_gate_group_m15_20260510T165500Z_20260511T023241Z/outputs/m14_vrp_pairwise_diff.json`
- m15_weak_acceptance: `/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_m15_weak_runs/m15_weak_completion_group_m15_20260510T162200Z_20260510T164422Z/checks/M15_weak_completion_acceptance.txt`