from typing import List


def lmap(func, it) -> List:
    return list(map(func, it))


def indent(text: str, spaces=4) -> str:
    indentation = " " * spaces
    output = []

    for line in text.splitlines():
        if len(line) == 0:
            output.append(line)
        else:
            output.append(indentation + line)

    return "\n".join(output)
