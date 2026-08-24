"""unclekk-safety-harness-evolution 打包配置（P1-11 修复：真正的 setuptools.setup）。

此前本文件是「JSON 伪装成 .py」——ast 解析得到单个 dict 表达式、无 setup() 调用，
导致 pip 打包静默无效；且 console_scripts 指向 harness_hooks:main（真实函数名是 _main）。
现改为标准 setuptools 配置。
"""
from setuptools import setup

setup(
    name="unclekk-safety-harness-evolution",
    version="1.1.13",
    description="Self-Evolving Safety Harness (SHE) for Multi-Agent Systems",
    long_description=(
        "Self-evolving Safety Harness workflow for multi-agent systems. When agents "
        "experience privilege escalation, failures, or indirect injection/poisoning, "
        "diagnose the responsible artifact, generate minimal patches, pass through "
        "three hard gates (backup / safety-utility gate / reject pool dedup), and "
        "write back to form a self-healing loop."
    ),
    long_description_content_type="text/markdown",
    author="unclekk",
    author_email="unclekk@sapiens-ai.com",
    license="MIT",
    keywords=["safety", "harness", "agent", "security", "multi-agent", "evolution"],
    url="https://github.com/unclekk/safety-harness-evolution",
    project_urls={
        "Issues": "https://github.com/unclekk/safety-harness-evolution/issues",
    },
    packages=["scripts"],
    package_dir={"scripts": "scripts"},
    py_modules=["utils"],
    python_requires=">=3.11",
    install_requires=["pyyaml>=6.0.1"],
    extras_require={"test": ["pytest>=8.0.0"]},
    entry_points={
        "console_scripts": [
            "she-apply=evolve_guard:main",
            "she-judge=evolve_guard:main",
            "she-backup=evolve_guard:main",
            "she-rollback=evolve_guard:main",
            "she-score=score_patch:main",
            "she-hooks=harness_hooks:_main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
