import argparse

from student.recursive_resolver import recursive_resolve
from student.iterative_resolver import iterative_resolve

RECURSIVE_DNS = "10.0.0.10"
ROOT_SERVER = "10.0.0.1"


def main() -> None:
    parser = argparse.ArgumentParser(description="Test the student DNS resolvers on one domain.")
    parser.add_argument("domain", help="Domain name to resolve, e.g. alpha.test")
    parser.add_argument("--mode", choices=["recursive", "iterative", "both"], default="both", help="Which resolver to test")
    args = parser.parse_args()

    domain = args.domain

    if args.mode in ("recursive", "both"):
        try:
            ip = recursive_resolve(domain, RECURSIVE_DNS)
            print(f"For domain {args.domain}, recursive: {ip}")
        except Exception as exc:
            print(f"recursive: ERROR: {exc}")

    if args.mode in ("iterative", "both"):
        try:
            ip = iterative_resolve(domain, ROOT_SERVER)
            print(f"For domain {args.domain}, iterative: {ip}")
        except Exception as exc:
            print(f"iterative: ERROR: {exc}")


if __name__ == "__main__":
    main()