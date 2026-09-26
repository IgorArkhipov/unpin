# Performance baselines

These are reproducible local measurements for the September 2026 audit changes, not cross-machine CI limits. Run each benchmark alone, from the repository root, with a release build:

```bash
cargo test --release -p unpin-core --test discovery_benchmark --locked -- --ignored --nocapture
cargo test --release -p unpin-core --test mcp --locked cached_mcp_inventory_benchmark -- --ignored --nocapture
cargo test --release -p unpin-cli --bin unpin --locked tui_search_redraw_and_preview_benchmark -- --ignored --nocapture
```

Measured on 2026-09-25 from `improve/2026-09-audit` (base `45db893`, dependency commit `c0d72ff`, plus the audit changes) on an Apple M5 Max with 36 GiB RAM, macOS 26.6.2, and Rust/Cargo 1.98.1. The three test processes ran sequentially. The discovery test reports one first run and the median of five warm runs. TUI and MCP report the median and 95th percentile of 30 warm samples per size. The test-only allocator counts allocation/reallocation events within each sample; those counts include response construction where applicable. It does not count deallocations or allocations made by the operating system outside Rust's allocator.

## Discovery

| Fixture directories | Skills | Items | First run | Warm median | Warm median allocations |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 16 | 68 | 38 ms | 38 ms | 19,433 |
| 2,048 | 128 | 516 | 401 ms | 294 ms | 143,819 |
| 8,192 | 512 | 2,052 | 1,201 ms | 1,271 ms | 570,448 |

The fixture directory count is a repeatable filesystem-work input, not a count of syscalls. The test's phase estimates compare separate runs and must not be interpreted as direct profiling attribution. No discovery implementation change was justified by this audit; scoped traversal dominates at the largest fixture.

## TUI

| Inventory items | Workload | Reference median | Prepared median | Reference allocations | Prepared allocations |
| ---: | --- | ---: | ---: | ---: | ---: |
| 128 | redraw with search | 24 µs | <1 µs | 1,123 | 17 |
| 1,024 | redraw with search | 161 µs | 2 µs | 8,966 | 129 |
| 4,096 | redraw with search | 676 µs | 7 µs | 35,848 | 513 |
| 4,096 | changing search | 632 µs | 104 µs | 36,864 | 4,110 |
| 4,096 | selected preview | 15 µs fresh | <1 µs cached | 39 fresh | 12 cached |

The reference redraw in the ignored test reproduces the previous filtering and row-formatting loop; it is not a second checkout of the old binary. The reference search update omits the old selection-clamping pass, so it is a conservative estimate. Prepared redraw still clones visible row strings. Search edits recompute the visible index but reuse normalized fields. The preview fixture has a missing source path, so the fresh-preview timing is a lower bound on filesystem-backed plans. A preview now calls `plan_toggle` once per selected item/discovery refresh rather than on every redraw. Staging and applying still perform fresh authoritative planning and validation.

## Cached MCP inventory

| Items | Workload | Median | P95 | Median allocations |
| ---: | --- | ---: | ---: | ---: |
| 128 | old deep clone only | 43 µs | 56 µs | 1,921 |
| 128 | scoped list, limit 10 | 37 µs | 50 µs | 1,000 |
| 128 | scoped summary | 61 µs | 155 µs | 1,867 |
| 1,024 | old deep clone only | 292 µs | 431 µs | 15,361 |
| 1,024 | scoped list, limit 10 | 57 µs | 72 µs | 1,000 |
| 1,024 | scoped summary | 206 µs | 251 µs | 7,243 |
| 4,096 | old deep clone only | 1,142 µs | 1,246 µs | 61,441 |
| 4,096 | scoped list, limit 10 | 142 µs | 156 µs | 1,000 |
| 4,096 | scoped summary | 665 µs | 681 µs | 25,675 |

The old-clone number is only the unavoidable deep-copy component of the previous request, not the entire previous request. These timed calls use a warm cache and therefore do no discovery traversal while the cache entry remains valid. Summary aggregation and JSON output still scale with the selected inventory; the bounded list no longer allocates in proportion to the full item count.

## Regression review budgets

On the same machine and toolchain, rerun a benchmark twice before investigating a regression. Review a discovery warm median or allocation count more than 25% above the corresponding baseline. At 4,096 items, review prepared redraw above 50 µs or 650 allocations, search updates above 200 µs or 5,000 allocations, cached list above 200 µs or 1,250 allocations, and cached summary above 900 µs or 32,000 allocations. These are investigation triggers, not automated pass/fail limits: scheduling, APFS cache state, and fixture differences can move small timings substantially. Review unexpected extra discovery refreshes or preview plans on redraw even when timing stays within budget.

Filesystem syscall counts and I/O bytes were not captured. The benchmarks record the fixture directory workload and the number of discovery/preview operations instead. If a later optimization targets filesystem traversal, add scoped syscall instrumentation on a sanitized fixture before claiming an I/O reduction.
