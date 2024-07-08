from typing import Optional, Dict
from .common import FilesystemRepository, FilesystemLoader
from .filesystemunifier import FilesystemUnifier

def _mounts_from_string(mappings: str) -> Dict[str, str]:
    '''
    From a mapping string, create a dictionary mapping mount_point -> archive_path
    Here archive_path should start with ./ and end with .tar.gz.

    Our input STRINGS store filesystem -> mount_point
    Our output DICTIONARY stores mount_point: filesystem
    '''
    mount_points = {}
    for mapping in mappings.split(","):
        parts = mapping.split(":")
        if len(parts) != 2:
            raise ValueError(f"Invalid mapping: {mapping}")
        archive = parts[0]
        destination = parts[1]

        # Ensure archive is a valid path to a tar.gz file in the input_path
        if not archive.endswith(".tar.gz"):
            archive += ".tar.gz"

        # Ensure relative destination
        if not destination.startswith("."):
            destination = "." + destination
        mount_points[destination] = archive
    return mount_points

def _mounts_to_string(mount_points: Dict[str, str]):
    '''
    Given a dictionary mapping mount_point -> archive_path, return a string
    representing this mapping
    '''
    maps = {}
    for mount_point, archive in mount_points.items():
        # mount_point: Trim leading .
        if mount_point.startswith("./"):
            mount_point = mount_point[1:]

        # Archive path: trim leading ./ and trailing .tar.gz
        if archive.startswith("./"):
            archive = archive[2:]
        if archive.endswith(".tar.gz"):
            archive = archive[:-7]

        maps[archive] = mount_point

    str_result = ""
    # We want to sort from shortest mount point to longest
    # and append each to the result string
    for archive, mount_point in sorted(maps.items(), key=lambda x: len(x[1])):
        str_result += f"{archive}:{mount_point},"
    return str_result[:-1] if len(str_result) else ""

def build_filesystem_from_map(input_path: str, output_path: str, mount_points: Dict[str, str], verbose: bool = False) -> None:
    '''
    Create a unified filesystem with a specified mount_points from files in the input_path
    '''

    repository = FilesystemRepository()
    loader = FilesystemLoader(repository)
    loader.load_filesystems(input_path)
    unifier = FilesystemUnifier(repository, verbose=verbose)

    if not len(mount_points):
        raise ValueError("No mount points provided")

    for archive in mount_points.values():
        if archive not in repository.filesystems:
            raise ValueError(f"Unknown archive: {archive}")

    unifier.create_archive(loader.load_path, mount_points, output_path)


def build_filesystem(input_path: str, output_path: str, mappings: str, verbose: bool = False) -> None:
    '''
    Create a unified filesystem with a specified mapping from files in the input_path
    '''
    mount_points = _mounts_from_string(mappings)
    return build_filesystem_from_map(input_path, output_path, mount_points, verbose=verbose)

def find_best_map(input_path: str, output_path: Optional[str] = None, verbose: bool = False):
    '''
    Given a directory (or a path to a .tar.gz within such a directory),
    examine all the archives and find an optimal way to unify them into a single filesystem.

    If an output path is provided, create a unified filesystem at that location.
    '''
    repository = FilesystemRepository()
    loader = FilesystemLoader(repository)
    loader.load_filesystems(input_path)
    unifier = FilesystemUnifier(repository, verbose=verbose)
    mount_points = unifier.unify()

    if output_path is not None:
        build_filesystem(input_path, mount_points, verbose=verbose)

    return mount_points

def main():
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Analyze and unify multiple filesystem partitions")
    parser.add_argument("--verbose", action="store_true", help="Print verbose output")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze the filesystems in the input path to identify the best mount points. If an output path is provided, create a unified filesystem at that location.")
    analyze_parser.add_argument("input_path", help="Path to a directory containing tar.gz files or a single tar.gz file")
    analyze_parser.add_argument("output_path", nargs="?", help="Path to write the unified filesystem")

    unify_parser = subparsers.add_parser("unify", help="Create a unified filesystem using the provided mappings")
    unify_parser.add_argument("input_path", help="Path to a directory containing tar.gz files or a single tar.gz file")
    unify_parser.add_argument("output_path", help="Path to write the unified filesystem")
    unify_parser.add_argument("mappings", help="Mappings of filesystems to mount points. Example: '1:/,2:/usr,3:/var'")

    args = parser.parse_args()

    if args.command == "analyze":
        result = find_best_map(args.input_path, args.output_path, args.verbose)
        print(_mounts_to_string(result))
    elif args.command == "unify":
        build_filesystem(args.input_path, args.output_path, args.mappings, args.verbose)
    else:
        print(f"Invalid command {args.command}. Use 'analyze' or 'unify'")
        sys.exit(1)

if __name__ == "__main__":
    main()