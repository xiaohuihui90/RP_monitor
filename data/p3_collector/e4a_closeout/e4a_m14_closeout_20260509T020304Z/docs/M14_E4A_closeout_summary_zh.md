# M14 / E4-A 阶段性收尾总结

生成时间：2026-05-09T02:03:22.206450+00:00

## 1. 运行标识

- run_id：`m14a_auto_group_20260508T064858Z`
- snapshot_group_id：`group_20260508T064858Z`
- scope：`m14_e4a_cross_region_same_validator`
- validator：`routinator`
- received_probes：`['probe-bj', 'probe-cd', 'probe-sg']`
- generated_time_skew_seconds：`442`

## 2. 当前范围

- 当前只做 E4-A：跨地域同 Routinator 输出差异。
- E4-B 跨 validator 仅预留接口。
- 控制面影响评估仅预留接口。
- 未安装新 validator，未加载 BGP 数据，未重启 Collector/Probe。

## 3. VRP set 对比结果

- all_vrp_roots_aligned：`False`
- all_pairwise_entry_level_diff_count：`440`
- min_pairwise_jaccard_similarity：`0.999749378692293`

### 3.1 Pairwise 差异与影响范围

#### probe-cd_vs_probe-bj
- entry_level_diff_count：`177`
- affected_prefix_count：`143`
- affected_asn_count：`69`
- common_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.only_right.txt`

#### probe-cd_vs_probe-sg
- entry_level_diff_count：`48`
- affected_prefix_count：`38`
- affected_asn_count：`22`
- common_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.only_right.txt`

#### probe-bj_vs_probe-sg
- entry_level_diff_count：`215`
- affected_prefix_count：`171`
- affected_asn_count：`84`
- common_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.only_right.txt`

## 4. 参数完整性

- vrp_count_exists：`True`
- vrp_digest_exists：`True`
- vrp_root_v1_exists：`True`
- vrp_set_path_exists：`True`
- vrp_set_diff_exists：`True`
- common_vrps_path_exists：`True`
- only_left_vrps_path_exists：`True`
- only_right_vrps_path_exists：`True`
- affected_prefix_count_exists：`True`
- affected_asn_count_exists：`True`
- validator_fingerprint_summary_exists：`True`
- e4b_reserved_only：`True`
- control_plane_impact_reserved_only：`True`

## 5. 严格 object context 复核

- original_same_window_candidate_count：`4`
- strict_same_window_object_context_count：`0`
- strict_object_context_available：`False`
- interpretation：Original discovery candidates are not sufficient as strict object-layer evidence.

P3 非严格 discovery 找到的候选项被 P3-R 严格复核否决。它们是 M14 verdict/evidence 文件，而不是 `object_set_root`、`effective_object_root`、`object_inventory` 或 `active_manifest` 等真实对象层观测证据。

## 6. 最终结论

- final_status：`blocked_object_layer_unverified`
- e4_status：`blocked`
- confirmed_allowed：`False`
- blockers：`['same_window_object_layer_context_missing']`
- warnings：`['original_object_context_discovery_candidates_rejected_by_strict_review', 'vrp_output_diff_observed_but_strict_same_window_object_context_missing']`

当前 VRP 输出差异已经被观测和量化，但由于缺少严格同窗对象层证据，不能提升为 E4 candidate 或 E4 confirmed。最终状态必须保持 `blocked_object_layer_unverified`。

## 7. 证据包

- e4a_evidence_pack_v2：`/home/zhangxiaohui/s3_stage3_v3_code/data/p3_collector/m14_vrp_runs/m14a_auto_group_20260508T064858Z/evidence/m14a_auto_group_20260508T064858Z_e4a_evidence_pack_v2.tar.gz`
- e4a_evidence_pack_v2_sha256：`38fbed168cb6920becfaf6a903e9e5a9efaa46742cd41ee146ae7067aa8d0f31`
- all_required_evidence_exists：`True`

## 8. 后续建议

1. 下一轮 VRP 自动采集时，同步触发对象层采集，生成同窗 `object_set_root / effective_object_root / active_manifest_records`。
2. 在严格同窗对象层证据存在后，再重新运行 P6 final verdict。
3. 当前阶段暂不启动跨 validator 和控制面影响真实评估。
