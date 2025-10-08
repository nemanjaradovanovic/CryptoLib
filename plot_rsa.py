import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# CSV se snima u build folderu
csv_path = Path("build") / "rsa_benchmark.csv"
if not csv_path.exists():
    raise FileNotFoundError(f"CSV not found at: {csv_path}")

df = pd.read_csv(csv_path)

# Filtriraj samo uspešne probe (Status == OK)
ok = df[df["Status"] == "OK"]

# Render funkcija
def plot_op(df, op_col, outfile):
    plt.figure(figsize=(7, 5))
    for msg_len in sorted(df["MsgLen"].unique()):
        subset = df[df["MsgLen"] == msg_len]
        subset = subset.sort_values("KeyBits")
        plt.plot(subset["KeyBits"], subset[op_col], marker="o", label=f"MsgLen={msg_len}")
    plt.title(f"RSA {op_col} vs Key Size")
    plt.xlabel("Key Size (bits)")
    plt.ylabel(f"{op_col} (ms)")
    plt.grid(True, alpha=0.3)
    plt.legend(title="Message length", loc="best")
    plt.tight_layout()
    plt.savefig(outfile, dpi=120)
    print(f"Saved {outfile}")

plot_op(ok, "KeyGenMS", "rsa_KeyGenMS.png")
plot_op(ok, "EncryptMS", "rsa_EncryptMS.png")
plot_op(ok, "DecryptMS", "rsa_DecryptMS.png")
print("All charts saved.")