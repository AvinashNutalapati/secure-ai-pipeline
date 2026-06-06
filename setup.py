from setuptools import setup, find_packages

setup(
    name="secure-ai-pipeline",
    version="1.0.0",
    description="Production-ready security pipeline for AI-generated code",
    author="AvinashNutalapati",
    license="MIT",
    url="https://github.com/AvinashNutalapati/secure-ai-pipeline",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["fastapi>=0.110", "uvicorn>=0.29", "requests>=2.31"],
    entry_points={"console_scripts": ["sap-mcp=extensions.claude_mcp.server:main"]},
)
