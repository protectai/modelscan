#!/usr/bin/env python3
"""
Script to update the TensorFlow safe operators list.

This script imports TensorFlow, extracts all raw operators, and updates
the JSON file used by modelscan to identify safe TensorFlow operations.

Usage:
    python scripts/update_tensorflow_operators.py

Requirements:
    - TensorFlow must be installed
    - Run from the project root directory
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any


def update_operators_json(json_path: Path) -> None:
    """
    Update the JSON file with new version and operators.

    Args:
        json_path: Path to the JSON file to update
    """
    try:
        import tensorflow as tf
    except ImportError:
        print("ERROR: TensorFlow is not installed.")
        print("Please install TensorFlow: pip install tensorflow")
        sys.exit(1)

    version: str = tf.__version__
    operators: List[str] = []
    for op in tf.raw_ops.__dict__.keys():
        operators.append(op)
    data: Dict[str, Any] = {}
    data[
        "description"
    ] = "List of known TensorFlow raw operators from tensorflow.raw_ops.__dict__.keys()"
    data["version"] = version
    data["operators"] = operators

    # Write updated file with nice formatting
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)


def main() -> None:
    """Main entry point."""
    # Determine paths
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    json_path = project_root / "modelscan" / "data" / "tensorflow_operators.json"

    update_operators_json(json_path)


if __name__ == "__main__":
    main()
