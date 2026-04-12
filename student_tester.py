#!/usr/bin/env python3
from __future__ import annotations

from student.recursive_resolver import recursive_resolve
from student.iterative_resolver import iterative_resolve

RECURSIVE_DNS = "10.0.0.10"
ROOT_SERVER = "10.0.0.1"

TEST_CASES = [
    {
        "name": "alpha.test",
        "acceptable_ips": {"10.1.1.1"},
        "description": "simple A record lookup",
    },
    {
        "name": "beta.test",
        "acceptable_ips": {"10.1.1.2"},
        "description": "iterative referral with multiple NS records and usable glue",
    },
    {
        "name": "gamma.test",
        "acceptable_ips": {"10.1.1.3"},
        "description": "A record lookup with extra unrelated A records in the additional section",
    },
    {
        "name": "delta.test",
        "acceptable_ips": {"10.1.1.4"},
        "description": "iterative referral where NS and glue order may be shuffled",
    },
    {
        "name": "epsilon.test",
        "acceptable_ips": {"10.1.1.5", "10.1.1.6"},
        "description": "domain with multiple valid A answers",
    },
    {
        "name": "zeta.test",
        "acceptable_ips": {"10.1.1.7"},
        "description": "iterative referral where only one NS has glue",
    },
    {
        "name": "eta.test",
        "acceptable_ips": {"10.1.1.8"},
        "description": "iterative referral containing bogus NS entries mixed with valid ones",
    },
    {
        "name": "alias.test",
        "acceptable_ips": {"10.1.1.20"},
        "description": "CNAME response that must be followed to the final A record",
    },
    {
        "name": "missing.test",
        "acceptable_ips": set(),
        "description": "NXDOMAIN response; resolver should return None",
    },
]


def check_result(name: str, ip: str | None, acceptable_ips: set[str]) -> None:
    if not acceptable_ips:
        if ip is not None:
            raise AssertionError(f"expected None, got {ip}")
        return

    if ip not in acceptable_ips:
        raise AssertionError(f"expected one of {sorted(acceptable_ips)}, got {ip}")


def run_test(case: dict, fn, label: str) -> bool:
    name = case["name"]
    acceptable_ips = case["acceptable_ips"]
    description = case["description"]

    print(f"[RUN ] {label} {name} -- {description}")

    try:
        if label == "Recursive":
            ip = fn(name, RECURSIVE_DNS)
        else:
            ip = fn(name, ROOT_SERVER)

        check_result(name, ip, acceptable_ips)

        if acceptable_ips:
            print(f"[PASS] {label} {name} -- returned {ip}\n")
        else:
            print(f"[PASS] {label} {name} -- returned None as expected\n")
        return True

    except Exception as exc:
        print(f"[FAIL] {label} {name} -- {description}")
        print(f"       error: {exc}\n")
        return False


def run_suite(label: str, fn) -> tuple[int, int]:
    print(f"=== {label} resolver tests ===\n")
    passed = 0
    total = 0

    for case in TEST_CASES:
        total += 1
        if run_test(case, fn, label):
            passed += 1

    print(f"{label} summary: {passed}/{total} passed\n")
    return passed, total


def print_test_explanations() -> None:
    print("Test case meanings:\n")
    for case in TEST_CASES:
        name = case["name"]
        acceptable_ips = case["acceptable_ips"]
        description = case["description"]

        if acceptable_ips:
            expected = ", ".join(sorted(acceptable_ips))
            print(f"- {name}: {description}. Expected final IP in {{{expected}}}.")
        else:
            print(f"- {name}: {description}. Expected result is None.")
    print()


def main() -> None:
    print_test_explanations()

    rec_passed, rec_total = run_suite("Recursive", recursive_resolve)
    itr_passed, itr_total = run_suite("Iterative", iterative_resolve)

    overall_passed = rec_passed + itr_passed
    overall_total = rec_total + itr_total
    print(f"Overall: {overall_passed}/{overall_total} passed")


if __name__ == "__main__":
    main()