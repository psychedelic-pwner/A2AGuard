"""Shared lab limits and tokens. Servers and checks import these so they cannot drift."""

MAX_BODY_BYTES = 64 * 1024
# Process ceiling so a lab client cannot exhaust memory. Far above the 64KB control.
ABSOLUTE_MAX_BODY_BYTES = 8 * 1024 * 1024

LAB_TOKEN_A = "a2aguard-lab-alpha"
LAB_TOKEN_B = "a2aguard-lab-beta"
UNKNOWN_TOKEN = "a2aguard-not-a-valid-token"
