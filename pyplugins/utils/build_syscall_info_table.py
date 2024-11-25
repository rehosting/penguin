import re
import pycparser
import pickle


def make_syscall_info_table():
    """
    Table format: arch -> nr -> (name, arg_names).
    The names do not have a sys_ prefix.
    """

    def parse_c(input):
        input = re.sub(r"\b__user\b", "", input)
        # We don't care about the types. Just replace them with int so parsing succeeds.
        types = [
            "size_t",
            "umode_t",
            "time_t",
            "old_uid_t",
            "old_gid_t",
            "off_t",
            "pid_t",
            "old_sigset_t",
            "qid_t",
            "loff_t",
            "fd_set",
            "sigset_t",
            "siginfo_t",
            "cap_user_header_t",
            "cap_user_data_t",
            "uid_t",
            "gid_t",
            "timer_t",
            "u64",
            "u32",
            "aio_context_t",
            "clockid_t",
            "mqd_t",
            "key_t",
            "key_serial_t",
            "__s32",
            "old_time32_t",
            "__sighandler_t",
            "caddr_t",
            "__u32",
            "rwf_t",
            "uint32_t",
        ]
        input = re.sub(rf"\b({'|'.join(types)})\b", "int", input)
        return pycparser.c_parser.CParser().parse(input)

    def parse_protos_file(arch):
        if arch == "mips64el":
            arch = "mips64"
        with open(f"/igloo_static/syscalls/linux_{arch}_prototypes.txt") as f:
            lines = [
                line.split(maxsplit=1)
                for line in f.readlines()
                if not line.startswith("//")
            ]

        return [(int(nr), parse_c(sig)) for nr, sig in lines]

    vals = {
        arch: {
            nr: (
                ast.ext[0].name.replace("sys_", ""),
                tuple(p.name for p in ast.ext[0].type.args.params),
            )
            for nr, ast in parse_protos_file(arch)
        }
        for arch in ("arm", "arm64", "mips", "mips64", "mips64el", "x64")
    }

    vals["aarch64"] = vals["arm64"]
    vals["intel64"] = vals["x64"]
    return vals


if __name__ == "__main__":
    with open("/igloo_static/syscall_info_table.pkl", "wb") as f:
        pickle.dump(make_syscall_info_table(), f)
