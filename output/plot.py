import matplotlib.pyplot as plt
import pandas as pd
import json
from adjustText import adjust_text


# This plot function is copied from Columbia University EECS4750 Assignment 4
def plot_stats(title, sizes, stats):
    # plot function
    x = list(range(1, len(sizes) + 1))
    plt.figure(figsize=(16, 8))
    plt.title(title)
    plt.xlabel("ASCII file size")
    plt.ylabel("Execution time including memory copy (ms)")

    texts = []
    n = len(stats)
    for label, t in stats.items():
        plt.plot(
            x,
            t,
            linestyle="--",
            marker="o",
            label="Function {}".format(label),
        )
    plt.yscale("log")

    plt.xticks(x, sizes)
    plt.legend()
    adjust_text(texts, arrowprops=dict(arrowstyle="->", color="black", lw=0.5))
    plt.savefig(title + ".png")
    plt.show()


def print_table(title, sizes, stats):
    fig, ax = plt.subplots()
    ax.axis("off")
    ax.axis("tight")

    for key in stats:
        for i in range(len(stats[key])):
            if stats[key][i] is None:
                stats[key][i] = ""
            elif isinstance(stats[key][i], float):
                stats[key][i] = "{:.5f} ms".format(stats[key][i])

    df = pd.DataFrame(stats)
    df.index = sizes
    ax.table(cellText=df.values, colLabels=df.columns, rowLabels=df.index, loc="center")

    plt.title(title)
    plt.savefig(title + "_table.png", dpi=200)
    plt.show()


with open("result.json", "r") as f:
    data = json.load(f)

sizes = data["file_sizes"]
length = len(sizes)
# translate sizes to KB, MB, GB if needed
sizes_adjusted = []
for size in sizes:
    if size < 1024:
        sizes_adjusted.append(str(size) + "B")
    elif size < 1024 * 1024:
        sizes_adjusted.append(str(size // 1024) + "KB")
    elif size < 1024 * 1024 * 1024:
        sizes_adjusted.append(str(size // (1024 * 1024)) + "MB")
    else:
        sizes_adjusted.append(str(size // (1024 * 1024 * 1024)) + "GB")


for key in data:
    if len(data[key]) < length:
        data[key] += [None] * (length - len(data[key]))
enc_data = {}
dec_data = {}
for key in data:
    if "enc" in key:
        enc_data[key] = data[key]
    elif "dec" in key:
        dec_data[key] = data[key]
plot_stats("AES128 Encryption", sizes_adjusted, enc_data)
plot_stats("AES128 Decryption", sizes_adjusted, dec_data)
print_table("AES128 Encryption", sizes_adjusted, enc_data)
print_table("AES128 Decryption", sizes_adjusted, dec_data)
