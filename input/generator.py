import random
import string

file_size = [2**i for i in range(14, 31, 2)]
for size in file_size:
    with open(f"input_{size}.txt", "w") as f:
        # f.write("a" * size)
        f.write("".join(random.choices(string.ascii_letters, k=size)))
