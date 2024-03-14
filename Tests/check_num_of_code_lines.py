from os import walk, path, getcwd, sep, pardir


def check_num_of_code_lines(repo_name: str) -> int:
    total_lines = 0
    for root, dirs, files in walk(repo_name):
        for file in files:
            if file.endswith(".py"):
                with open(path.join(root, file), "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in lines:
                        line = line.strip()
                        # Exclude imports and comments
                        if line and not line.startswith("#") and not line.startswith("import") and not line.startswith("from"):
                            total_lines += 1
    return total_lines


full_path = path.normpath(getcwd() + sep + pardir)
print(check_num_of_code_lines(repo_name=full_path))