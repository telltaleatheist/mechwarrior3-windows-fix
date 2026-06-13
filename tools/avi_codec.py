import struct
p = r"C:\Games\MechWarrior3\video\C1M1.AVI"
data = open(p,"rb").read(4096)
i = data.find(b"strf")
if i>=0:
    bih = data[i+8:i+8+40]
    biSize, biW, biH = struct.unpack("<iii", bih[0:12])
    biBitCount = struct.unpack("<H", bih[14:16])[0]
    biComp = bih[16:20]
    print(f"video: {biW}x{biH}, {biBitCount}bpp, compression FourCC = {biComp!r} ({biComp.decode('latin1')})")
i2 = data.find(b"strh")
if i2>=0:
    fcc = data[i2+8:i2+16]
    print(f"strh type+handler = {fcc!r}")
