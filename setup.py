from setuptools import setup, find_packages

setup(
    name="secure-ai-pipeline",
    version="3.0.1",
    description="Security for AI-assisted development — AI Agent Blast Radius checkup + code pipeline",
    author="AvinashNutalapati",
    license="MIT",
    url="https://github.com/AvinashNutalapati/secure-ai-pipeline",
    # Only the extensions package ships in the wheel. scripts/ is delivered by
    # the installer/Action; packaging it would drop an orphan `scripts.scanners`
    # (scripts/ has no __init__.py) and squat generic top-level names.
    packages=find_packages(include=["extensions", "extensions.*"]),
    python_requires=">=3.10",
    install_requires=["mcp>=1.2", "fastapi>=0.110", "uvicorn>=0.29", "requests>=2.31"],
    entry_points={
        "console_scripts": [
            "sap-mcp=extensions.claude_mcp.mcp_server:main",   # MCP stdio server (Claude Code)
            "sap-rest=extensions.claude_mcp.server:main",       # REST server (OpenAI GPT Action)
        ]
    },
)
