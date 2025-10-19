from . import PatchGenerator

class RootShell(PatchGenerator):
    '''
    Add root shell
    '''
    def __init__(self) -> None:
        self.patch_name = "root_shell"
        self.enabled = False

    def generate(self, patches: dict) -> dict:
        return {
            "core": {
                "root_shell": False,
            },
        }
