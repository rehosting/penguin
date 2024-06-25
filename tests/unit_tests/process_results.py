import argparse
import json
import os
from pathlib import Path

def process_results(input_dir, output_file):
    all_results = {}
    
    for filename in os.listdir(input_dir):
        if filename.startswith("test_results_") and filename.endswith(".json"):
            with open(Path(input_dir) / filename, 'r') as f:
                results = json.load(f)
                all_results.update(results)
    
    # Create a summary
    summary = {
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "details": all_results
    }
    
    for kernel in all_results.values():
        for arch in kernel.values():
            for result in arch.values():
                summary["total_tests"] += 1
                if result == "PASS":
                    summary["passed_tests"] += 1
                else:
                    summary["failed_tests"] += 1
    
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Process PENGUIN test results.")
    parser.add_argument('--input-dir', required=True, help='Directory containing test result JSON files')
    parser.add_argument('--output-file', required=True, help='Output file for the summary')
    args = parser.parse_args()

    process_results(args.input_dir, args.output_file)

if __name__ == "__main__":
    main()