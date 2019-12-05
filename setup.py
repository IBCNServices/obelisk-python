import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="obelisk-client",
    version="0.0.1",
    author="Sander Borny",
    author_email="sander.borny@ugent.be",
    description="Client library for Obelisk.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IBCNServices/obelisk-python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "License :: OSI Approved :: GNU Affero General Public License v3",
    ],
    install_requires=["requests", "backoff"],
    python_requires='>=3.5',
)