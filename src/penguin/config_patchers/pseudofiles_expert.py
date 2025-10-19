from . import PatchGenerator
from penguin.defaults import expert_knowledge_pseudofiles

class PseudofilesExpert(PatchGenerator):
    '''
    Fixed set of pseudofile models from FirmAE.
    '''
    def __init__(self) -> None:
        self.enabled = True
        self.patch_name = "pseudofiles.expert_knowledge"

    def generate(self, patches: dict) -> dict:
        return {'pseudofiles': expert_knowledge_pseudofiles}
