import sys
hexresult = sys.argv[1]
h = hexresult[2:] if hexresult.startswith('0x') else hexresult
length = int(h[64:128], 16)
data = h[128:128 + length * 2]
print(bytes.fromhex(data).decode('utf-8', 'replace'))
