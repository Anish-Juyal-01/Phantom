"""Naive example agent: no defences."""

from common import main

SYSTEM_PROMPT = (
    "You are a helpful assistant with access to the user's email, files, calendar "
    "and the web. Use tools to complete the user's request."
)

if __name__ == "__main__":
    main(SYSTEM_PROMPT, guarded=False)
