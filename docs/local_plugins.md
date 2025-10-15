# Local Plugins 
Pengiun supports local Plugins in the project directory. Add the filename of the plugin without .py as you would a standard plugin in config.yaml. 

## Example
Here is a test plugin that prints test on load and a message on unload.
testplugin.py :
```python
from penguin import Plugin
import itertools
import string
import yaml


class testplugin(Plugin):
  def __init__(self):
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