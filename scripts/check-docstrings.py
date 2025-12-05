import subprocess
import sys

# TODO: Use the "mojo doc" directly when there is an option to
# fail if warnings are present (something like -Werror for gcc).


def main():
    # This is actually faster than running "mojo doc" on each file since
    # "mojo doc" only accept a single file/path as argument
    command = [
        "mojo",
        "doc",
        "--diagnose-missing-doc-strings",
        "-o",
        "/dev/null",
        "lightbug_http",
    ]
    result = subprocess.run(command, capture_output=True)
    if result.stderr or result.returncode != 0:
        print("Docstring issue found: ")
        print(result.stderr.decode())
        sys.exit(1)


if __name__ == "__main__":
    main()
