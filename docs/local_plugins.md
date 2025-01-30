# Local Plugins 
Pengiun supports local PyPlugins in the project directory. Add the filename of the plugin without .py as you would a standard plugin in config.yaml. PyPanda docs are available here:  [https://docs.panda.re/](https://docs.panda.re/)

## Example
Here is a test plugin that prints test on load and a message on unload.
testplugin.py :
```python
from pandare2 import PyPlugin
import itertools
import string
import yaml


class testplugin(PyPlugin):
        def __init__(self, panda):
            self.panda = panda
            self.outdir = self.get_arg("outdir")
            print("Put your code here")
        def uninit(self):
            print("testplugin uninit")  
```
Here is the changes to the config needed to enable said test plugin.
```yaml
plugins:
  testplugin:
    description: 'test plugin'
    version: 1.0.0
```