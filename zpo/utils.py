import shutil
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


def copy_file(source, destination):
    shutil.copy2(source, destination)


def copy_tree(source, destination, dirs_exist_ok=False):
    shutil.copytree(source, destination, dirs_exist_ok=dirs_exist_ok)
