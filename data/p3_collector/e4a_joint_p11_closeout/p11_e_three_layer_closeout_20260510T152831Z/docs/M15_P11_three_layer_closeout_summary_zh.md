# M15 / P11 三层视图联合归因闭环工程收口报告

## 1. 基本信息

snapshot_group_id: group_joint_20260509T094400Z

closeout_time_utc: 2026-05-10T15:28:58.586059+00:00

## 2. 最终结论

final_status: not_e4_object_layer_divergence_with_l1_retrofit_context
strict_three_layer_status: blocked_l1_window_mapping_not_strong
e4_status: blocked
confirmed_allowed: False
blocking_layer: object_layer
attribution_layer: object_view
confidence: medium-high

## 3. 三层状态摘要

### L1 宣告视图层

collection_mode: retrofit_or_diagnostic
window_mapping_level: weak_or_unknown
generated_time_skew_seconds: 76618
strict_announced_view_aligned: False
semantic_announced_view_aligned: True
all_pairwise_diff_count: 8

### L2 对象视图层

object_layer_aligned: False
object_roots_aligned: False
effective_object_roots_aligned: False
all_pairwise_inventory_diff_count: 625544
all_pairwise_active_manifest_diff_count: 624856

### L3 验证输出层

vrp_layer_aligned: False
all_vrp_roots_aligned: False
all_pairwise_entry_level_diff_count: 9722
min_pairwise_jaccard_similarity: 0.9943412194608036

## 4. 工程解释

本轮 P11 完成了 L1 宣告视图、L2 对象视图、L3 验证输出视图的联合门控与证据封装。

由于本轮 L1 是 retrofit_or_diagnostic 补采，L1 window_mapping_level 不是 strong，因此 strict_three_layer_status 被标记为 blocked_l1_window_mapping_not_strong。

同时，P9/P10 已经在强同窗对象层和 VRP 层证据下确认 object_layer_divergence_observed，因此最终保守结论仍然是：不允许确认 E4-A，当前阻断层为 object_layer。

## 5. 当前限制

1. L1 宣告视图为 retrofit_or_diagnostic 补采，不是严格三层同窗采集。
2. object_source_mode 仍是 cache_file_inventory，不完全等价于 validator active-object decision。
3. E4-B cross-validator 仍为 reserved_only。
4. control-plane impact 仍为 reserved_only。
5. 后续需要重新跑 group_m15_* strict strong group 作为最终三层强同窗样例。

## 6. 证据包

evidence_pack: /home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_p11_closeout/p11_e_three_layer_closeout_20260510T152831Z/evidence/group_joint_20260509T094400Z_p11_three_layer_joint_attribution_evidence.tar.gz
evidence_pack_sha256_file: /home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/e4a_joint_p11_closeout/p11_e_three_layer_closeout_20260510T152831Z/evidence/group_joint_20260509T094400Z_p11_three_layer_joint_attribution_evidence.tar.gz.sha256

## 7. 下一步

建议进入 Batch 6，重新构造一个 group_m15_*，三地尽量同步采集 L1/L2/L3，形成严格三层 strong-window 工程验收样例。
