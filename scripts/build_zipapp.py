#!/usr/bin/env python3
import argparse
import os
import shutil
import tempfile
import zipapp


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build single-file AgentSecure trial zipapp")
    parser.add_argument("--output", default="dist/agentsecure.pyz", help="Output .pyz path")
    args = parser.parse_args()

    output_path = os.path.abspath(args.output)
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_dir:
        build_root = os.path.join(temp_dir, "agentsecure_zipapp")
        package_dest = os.path.join(build_root, "agentsecure")
        shutil.copytree(os.path.join(REPO_ROOT, "agentsecure"), package_dest)
        with open(os.path.join(build_root, "__main__.py"), "w") as handle:
            handle.write("from agentsecure.cli.main import main\n")
            handle.write("raise SystemExit(main())\n")
        zipapp.create_archive(
            build_root,
            target=output_path,
            interpreter="/usr/bin/env python3",
            compressed=True,
        )

    print("Built %s" % output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
