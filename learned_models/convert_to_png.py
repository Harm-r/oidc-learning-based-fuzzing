import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("Usage: convert_to_png.py input.dot output.png")

subprocess.run(
    ["dot", "-Tpng", sys.argv[1], "-o", sys.argv[2]],
    check=True,
)