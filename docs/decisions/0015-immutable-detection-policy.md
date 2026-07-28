# 0015 Immutable Detection Policy

Detection policies are immutable versioned records with deterministic policy hashes.

The default `hybrid-policy-v1` is built in and Pydantic-validated. Policy JSON cannot carry
arbitrary Python, SQL, shell commands, model artifact paths, or executable code.
