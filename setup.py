import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="helios_lib",
    version="0.0.2",
    author="Omid Raha",
    author_email="or@omidraha.com",
    description="Helios Server (Helios is an end-to-end verifiable voting system) as library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anarvote/helios_lib",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License"
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'pytest==3.6.2'],
)

