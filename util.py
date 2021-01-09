import os

# From: https://stackoverflow.com/a/59803793
def run_fast_scandir(dir, ext = [], names = []):    # dir: str, ext: list
    subfolders, files = [], []

    for f in os.scandir(dir):
        if f.is_dir():
            subfolders.append(f.path)
        if f.is_file():
            add = False
            extMatch = os.path.splitext(f.name)[1].lower() in ext
            # Break if at least one name matched
            nameMatch = False
            for name in names:
                nameMatch = name in f.name.lower()
                if nameMatch: 
                    break

            if ext != [] and names != []:
                if extMatch and nameMatch:
                    add = True
            elif ext != []:
                if extMatch:
                    add = True
            elif names != []:
                if nameMatch:
                    add = True
            else:
                add = True

            if add:
                files.append(f.path)

    for dir in list(subfolders):
        sf, f = run_fast_scandir(dir, ext, names)
        subfolders.extend(sf)
        files.extend(f)
    return subfolders, files