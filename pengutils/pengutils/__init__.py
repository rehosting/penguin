"""
Pengutils
=========

General-purpose utilities, data models, and CLI tools for the Penguin system.
Provides reusable functions, database models, and helpers for querying, filtering, and analyzing Penguin and interacting with a running system.

Usage
-----

Pengutils can be used in two main ways:

1. **Inside the Penguin container**: All utilities and CLI tools are available by default when running inside the official Penguin container environment.
2. **Outside the Penguin container**: You can install pengutils from source and use its modules and CLI tools independently. Clone the repository and install with pip:

   .. code-block:: bash

       git clone https://github.com/rehosting/penguin.git
       cd penguin/pengutils
       pip install .

This allows you to run pengutils commands and import its modules in your own Python environment, provided you have access to the Penguin results database.

Once installed you can run a series of CLI tools for querying and processing Penguin data, as well as importing its data models and utilities in your own Python scripts.
"""
