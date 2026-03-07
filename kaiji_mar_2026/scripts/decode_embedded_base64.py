#!/usr/bin/env python3
"""Decode embedded Base64 token(s) recovered from the sample."""

from __future__ import annotations

import argparse
import base64


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("token", nargs="?", default="YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=")
    args = ap.parse_args()

    raw = base64.b64decode(args.token)
    print(raw.decode("utf-8", "ignore"))


if __name__ == "__main__":
    main()
