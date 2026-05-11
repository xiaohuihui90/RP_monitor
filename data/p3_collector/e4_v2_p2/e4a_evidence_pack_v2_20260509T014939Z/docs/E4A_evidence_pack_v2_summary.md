# E4-A Evidence Pack v2 Summary

- run_id: `m14a_auto_group_20260508T064858Z`
- snapshot_group_id: `group_20260508T064858Z`
- scope: `m14_e4a_cross_region_same_validator`
- comparison_type: `cross_region_same_validator`
- validator: `routinator`
- final_status: `blocked_object_layer_unverified`
- e4_status: `blocked`
- confirmed_allowed: `False`
- all_pairwise_entry_level_diff_count: `440`
- min_pairwise_jaccard_similarity: `0.999749378692293`
- generated_time_skew_seconds: `442`
- evidence_pack_sha256: `38fbed168cb6920becfaf6a903e9e5a9efaa46742cd41ee146ae7067aa8d0f31`

## 当前解释

本 evidence pack v2 固化了当前 E4-A 跨地域同 Routinator 的 VRP set diff、参数增强结果、validator fingerprint summary、control-plane impact placeholder 和 P6 final verdict。

当前不启动 E4-B 跨 validator 开发，也不加载 BGP 数据。最终状态仍为 blocked_object_layer_unverified，原因是缺少同窗 object layer context。
