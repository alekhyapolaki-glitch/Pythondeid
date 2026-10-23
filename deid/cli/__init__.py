"""Command-line interface. parser.py routes commands to the *_commands modules."""

from .parser import build_parser, main

__all__ = ["build_parser", "main"]
