file_size = [2**i for i in range(19, 33, 3)]
for size in file_size:
    with open(f"input_{size}.txt", "w") as f:
        f.write("0123456789abcdef" * (size // 16))
