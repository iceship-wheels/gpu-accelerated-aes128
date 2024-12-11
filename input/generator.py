import random
import string


def random_string(length):
    letters = string.ascii_letters
    return "".join(random.choice(letters) for i in range(length))


file_size = [2**i for i in range(13, 30, 3)]
for size in file_size:
    with open(f"input_{size}.txt", "w") as f:
        f.write(random_string(size))
