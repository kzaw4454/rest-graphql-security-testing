# Burp Suite benchmarking

Burp Suite is not scripted as part of this framework's automated benchmark
runs. Unlike OWASP ZAP (`benchmarks/zap_runner.py`, driven headlessly via
its REST API) and GraphQL Cop (`benchmarks/graphql_cop_runner.py`, driven
as a CLI subprocess), Burp Suite's scan workflow is not practically
automatable from a script for this project's scope and timeline.

Burp Suite runs, if performed, are manual: launch Burp against the same
target endpoints listed in `config/benchmark_mapping.yaml`, record findings
by hand, and note them directly in the dissertation's benchmarking section
rather than as logged `VulnerabilityResult` rows. There is no
`source=BURP` value in `src/vulnerabilities/base.py`'s `ResultSource` enum
for this reason -- it has nothing to log programmatically.
