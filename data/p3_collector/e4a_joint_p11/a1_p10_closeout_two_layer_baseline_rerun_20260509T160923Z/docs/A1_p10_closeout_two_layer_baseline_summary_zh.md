# A1 P10 Closeout：二层联合归因基线固化

## 基线信息

snapshot_group_id: group_joint_20260509T094400Z

当前 P10 结论:
- final_status: not_e4_object_layer_divergence
- e4_status: blocked
- confirmed_allowed: False
- blocking_layer: object_layer
- confidence: high

## L2 对象层

- final_status: object_layer_divergence_observed
- object_roots_aligned: False
- effective_object_roots_aligned: False
- all_pairwise_inventory_diff_count: 625544
- all_pairwise_active_manifest_diff_count: 624856

## L3 VRP 输出层

- all_vrp_roots_aligned: False
- all_pairwise_entry_level_diff_count: 9722
- min_pairwise_jaccard_similarity: 0.9943412194608036

## 工程意义

该基线证明：即使 VRP 输出层存在差异，只要对象层已经发生分裂，系统也不会误报 E4-A。后续 P11 将补入 L1 宣告视图层，形成三层联合归因闭环。

## 当前限制

1. A1 是二层基线固化，不包含 L1 announced view。
2. 当前 object_source_mode 仍是 cache_file_inventory，不完全等价于 validator active-object decision。
3. E4-B cross-validator 与 control-plane impact 仍为 reserved_only。
