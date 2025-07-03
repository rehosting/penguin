from penguin import Plugin

class Coverage(Plugin):
    """
    Previous versions of penguin had a coverage plugin that was referenced, but
    not often used by users. This plugin exists to make compatability with 
    older configs easier, but it does not provide any functionality.
    """
    def __init__(self):
        assert False, "Coverage plugin is not supported in this version of penguin"