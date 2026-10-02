# Evaluation Subset: Standard Benchmark 📊

## Purpose
The `standard` evaluation directory is reserved for representative, in-distribution test samples derived from verified real-world sources and public corpora.

## Policy & Governance
- **Strict Isolation**: Samples in this subset must remain strictly isolated from training and hyperparameter tuning datasets.
- **Leakage Prevention**: All samples must respect `pattern_group_id` boundaries. No pattern group present in the training corpus may appear in the standard evaluation split.
- **Metrics Target**: Evaluates overall precision, recall, and multi-label tactic accuracy under typical operational conditions.
- **Current Status**: No evaluation data is generated or stored at this stage. Real-world benchmark sets will be populated in subsequent phases.
