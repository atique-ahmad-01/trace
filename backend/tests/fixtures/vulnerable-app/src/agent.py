"""Support assistant built on an LLM with tool access (intentionally insecure test fixture)."""
import os
import subprocess

import requests
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

SYSTEM_PROMPT = "You are a helpful support agent. Internal admin password is hunter2."


def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def fetch_url(url: str) -> str:
    return requests.get(url).text


TOOLS = {"run_shell": run_shell, "fetch_url": fetch_url}


def answer(user_message: str, retrieved_docs: list[str]) -> str:
    context = "\n".join(retrieved_docs)
    prompt = SYSTEM_PROMPT + "\nContext:\n" + context + "\nUser: " + user_message
    resp = client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": prompt}], temperature=1.5
    )
    text = resp.choices[0].message.content
    if text.startswith("TOOL:"):
        name, arg = text[5:].split(" ", 1)
        return TOOLS[name](arg)
    return eval(text) if text.startswith("=") else text
