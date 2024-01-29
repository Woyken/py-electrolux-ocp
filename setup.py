import setuptools

with open("README.md", "r") as readmeFile:
    long_description = readmeFile.read()

setuptools.setup(
    author="Woyken",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Topic :: Home Automation",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    description="Electrolux OneApp OCP API",
    install_requires=["aiohttp"],
    keywords="home automation electrolux aeg ocp oneapp api",
    license="MIT License",
    long_description_content_type="text/markdown",
    long_description=long_description,
    name="pyelectroluxocp",
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    url="https://github.com/Woyken/py-electrolux-ocp",
    version="0.0.7",
    zip_safe=False,
)
