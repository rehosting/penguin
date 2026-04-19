from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import expert_knowledge_pseudofiles

class PseudofilesExpert(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = "pseudofiles.expert_knowledge"

    def generate(self, patches: dict) -> dict:
        return {'pseudofiles': expert_knowledge_pseudofiles}
