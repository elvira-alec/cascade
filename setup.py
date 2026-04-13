from setuptools import setup, find_packages

setup(
    name            = "cascade",
    version         = "1.0.0",
    packages        = find_packages(),
    entry_points    = {"console_scripts": ["cascade=cascade.__main__:main"]},
    install_requires= ["requests", "paramiko"],
    python_requires = ">=3.10",
)
