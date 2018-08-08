import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="zap_report_formatter",
    version="0.0.2",
    author="Wong Her Laang",
    author_email="wongherlung@gmail.com",
    description="Takes in OWASP ZAP json reports and produces whitelisted xml reports for Jenkins Junit plugin.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wongherlung/zap_report_formatter",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

# NOTE: To upload a new version of spader
# python setup.py sdist bdist_egg upload
