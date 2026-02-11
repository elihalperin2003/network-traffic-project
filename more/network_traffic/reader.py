import csv
def read(path):
    with open(path, "r") as fi:
        return list(csv.reader(fi))

