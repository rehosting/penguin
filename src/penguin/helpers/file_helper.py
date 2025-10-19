import os
import re
import subprocess
from pathlib import Path

class FileHelper:
    @staticmethod
    def find_executables(tmp_dir: str, target_dirs: set[str] | None = None):
        if not target_dirs:
            target_dirs = {"/"}
        for root, _, files in os.walk(tmp_dir):
            if "/igloo" in root:
                continue
            for file in files:
                file_path = Path(root) / file
                if (
                    file_path.is_file()
                    and os.access(file_path, os.X_OK)
                    and any(str(file_path).endswith(d) for d in target_dirs)
                ):
                    yield file_path

    @staticmethod
    def find_strings_in_file(file_path: str, pattern: str) -> list[str]:
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        return [line for line in result.stdout.splitlines() if re.search(pattern, line)]

    @staticmethod
    def find_shell_scripts(tmp_dir: str):
        for root, _, files in os.walk(tmp_dir):
            if "/igloo" in root:
                continue
            for file in files:
                file_path = Path(root) / file
                if (
                    file_path.is_file()
                    and os.access(file_path, os.X_OK)
                    and str(file_path).endswith(".sh")
                ):
                    yield file_path

    @staticmethod
    def exists(tmp_dir: str, target: str) -> bool:
        assert target.startswith("/")
        assert os.path.exists(tmp_dir)
        target = target[1:]
        parts = target.split("/")
        current_path = tmp_dir
        for part in parts:
            next_path = os.path.join(current_path, part)
            if os.path.islink(next_path):
                resolved = os.readlink(next_path)
                if resolved.startswith("/"):
                    current_path = os.path.realpath(os.path.join(tmp_dir, resolved[1:]))
                else:
                    current_path = os.path.realpath(os.path.join(current_path, resolved))
            else:
                current_path = next_path
            if not os.path.exists(current_path):
                return False
        return os.path.exists(current_path)
