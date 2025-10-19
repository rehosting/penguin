import tarfile

class TarHelper:
    '''
    Collection of static method to help find files in a tar archive
    '''
    @staticmethod
    def get_symlink_members(tarfile_path: str) -> dict[str, str]:
        with tarfile.open(tarfile_path, "r") as tar:
            return {
                member.name[1:]: member.linkname
                for member in tar.getmembers()
                if member.issym()
            }

    @staticmethod
    def get_all_members(tarfile_path: str):
        with tarfile.open(tarfile_path, "r") as tar:
            return tar.getmembers()

    @staticmethod
    def get_other_members(tarfile_path: str):
        with tarfile.open(tarfile_path, "r") as tar:
            return {
                member.name[1:]
                for member in tar.getmembers()
                if not member.isfile() and not member.isdir
            }

    @staticmethod
    def get_directory_members(tarfile_path: str) -> set[str]:
        with tarfile.open(tarfile_path, "r") as tar:
            results = {member.name[1:] for member in tar.getmembers() if member.isdir()}
        for r in list(results):
            parts = r.split("/")
            for i in range(len(parts)):
                results.add("/".join(parts[: i + 1]))
        return results

    @staticmethod
    def get_file_members(tarfile_path: str) -> set[str]:
        with tarfile.open(tarfile_path, "r") as tar:
            return {member.name[1:] for member in tar.getmembers() if member.isfile()}
