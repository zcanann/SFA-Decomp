import os

def fix_file(path):
    with open(path, "rb") as f:
        data = f.read()

    # Normalize CRLF / CRCRLF / stray CR to LF
    data = data.replace(b"\r\r\n", b"\n")
    data = data.replace(b"\r\n", b"\n")
    data = data.replace(b"\r", b"\n")

    # Collapse multiple blank lines caused by double newlines
    while b"\n\n\n" in data:
        data = data.replace(b"\n\n\n", b"\n\n")

    with open(path, "wb") as f:
        f.write(data)

for name in os.listdir("."):
    if name.lower().endswith(".c") and os.path.isfile(name):
        fix_file(name)
        print("fixed:", name)

print("done.")
