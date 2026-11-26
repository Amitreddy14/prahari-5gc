"""Prahari-5GC attack injector.

Lab use only. Every packet goes through `guard`, which refuses any destination or
spoofed source outside the testbed network 172.22.0.0/24. That bound is a constant,
not a setting.
"""

__version__ = "0.2.0"
