import os
from penguin import Plugin
from ratarmountcore.mountsource.factory import open_mount_source


class StaticFS(Plugin):
    def __init__(self):
        self.fs_tar = self.get_arg("fs")
        self.fs_dir = os.path.dirname(os.path.abspath(self.fs_tar))
        self.fs = open_mount_source(self.fs_tar, lazyMounting=True)
