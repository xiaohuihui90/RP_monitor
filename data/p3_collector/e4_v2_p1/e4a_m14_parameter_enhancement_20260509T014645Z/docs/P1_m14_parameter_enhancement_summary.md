# P1 M14 参数增强与 E4-A enriched diff 总结

- run_id：`m14a_auto_group_20260508T064858Z`
- active_scope：`m14_e4a_cross_region_same_validator`
- e4b_cross_validator：`reserved_only`
- control_plane_impact：`reserved_only`

## 1. 已补齐字段

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

## 2. Pairwise enriched diff

### probe-cd_vs_probe-bj
- entry_level_diff_count：`177`
- jaccard_similarity：`0.9997936716651745`
- affected_prefix_count：`143`
- affected_asn_count：`69`
- common_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-bj.only_right.txt`

### probe-cd_vs_probe-sg
- entry_level_diff_count：`48`
- jaccard_similarity：`0.9999440452487421`
- affected_prefix_count：`38`
- affected_asn_count：`22`
- common_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-cd_vs_probe-sg.only_right.txt`

### probe-bj_vs_probe-sg
- entry_level_diff_count：`215`
- jaccard_similarity：`0.999749378692293`
- affected_prefix_count：`171`
- affected_asn_count：`84`
- common_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.common.txt`
- only_left_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.only_left.txt`
- only_right_vrps_path：`diffs/_lowmem_work/probe-bj_vs_probe-sg.only_right.txt`

## 3. 当前解释

本批只增强 E4-A 跨地域同 Routinator 的 VRP set 对比参数，不启动跨 validator 和控制面影响评估。
当前 final verdict 仍应保持 blocked_object_layer_unverified，不能因为 VRP 差异直接确认 E4。
