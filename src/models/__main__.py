"""CLI entry point for running Phase 3 baseline training: python -m src.models"""

from .train_baseline import train_baseline


def main() -> None:
    train_baseline()


if __name__ == "__main__":
    main()
