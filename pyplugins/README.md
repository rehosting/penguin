# PyPlugins

PyPlugins are a way to extend the functionality of penguin. They are built on the PyPANDA core functionality and extend that functionality. [pandare documentation])(https://docs.panda.re/)

Find more information in the local docs [docs](../docs/pyplugin_architecture.md).

## Organization

PyPlugins are loosely organized into the following categories:
- `actuation`: Plugins that interact with the running system
- `analysis`: Plugins that perform analysis on the running system
- `hyper`: Plugins that use hypercall APIs
- `interventions`: Plugins that modify the running system
- `resources`: Information relevant to plugins
- `testing`: Plugins that are part of our CI/CD testing pipeline
- `utils`: Scripts that set things up for our plugins
