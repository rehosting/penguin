from penguin import Plugin, plugins
import os


class TaskSizeVerify(Plugin):
    def __init__(self):
        super().__init__()
        self.outdir = self.get_arg("outdir")
        self.conf = self.get_arg("conf")

    @plugins.syscalls.syscall("on_sys_ioctl_return", comm_filter="send_syscall",
                              arg_filters=[0x17, 0x1234])
    def verify_task_size(self, regs, proto, syscall, fd, op, arg):
        self.logger.info("TaskSizeVerify: Triggered")

        # Get expected task size from config context
        expected_str = self.conf.get('env', {}).get('igloo_task_size')
        if not expected_str:
            self.logger.error("TaskSizeVerify: No igloo_task_size in config!")
            return

        expected = int(expected_str, 16)

        # Get actual task size via OSI
        proc = yield from plugins.osi.get_proc()
        if not proc:
            self.logger.error("TaskSizeVerify: Could not get proc info")
            return

        actual = proc.task_size
        self.logger.info(
            f"TaskSizeVerify: Expected={expected:#x}, Actual={actual:#x}")

        # Also check mappings to ensure nothing is above the limit
        mappings = yield from plugins.osi.get_mappings()
        max_addr = 0
        if mappings:
            for m in mappings:
                if m.end > max_addr:
                    max_addr = m.end

        self.logger.info(f"TaskSizeVerify: Max mapping end={max_addr:#x}")

        passed = True
        if actual != expected:
            self.logger.error(
                f"TaskSizeVerify: FAIL - actual task_size {actual:#x} != expected {expected:#x}")
            passed = False

        if max_addr > expected:
            self.logger.error(
                f"TaskSizeVerify: FAIL - mapping end {max_addr:#x} exceeds task_size {expected:#x}")
            passed = False
            for m in mappings:
                self.logger.info(
                    f"Mapping: {m.start:#x} - {m.end:#x} {m.name}")

        result = "passed" if passed else "failed"

        with open(os.path.join(self.outdir, "task_size_test.txt"), "w") as f:
            f.write(f"Task size test: {result}\n")
            if not passed:
                f.write(
                    f"Actual: {actual:#x}, Expected: {expected:#x}, Max Mapping: {max_addr:#x}\n")

        syscall.retval = 0 if passed else 1
