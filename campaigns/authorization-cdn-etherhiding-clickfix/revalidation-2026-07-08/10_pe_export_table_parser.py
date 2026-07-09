import struct, sys

path = sys.argv[1]
with open(path, 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
pe_off = e_lfanew
assert data[pe_off:pe_off+4] == b'PE\x00\x00'
coff_off = pe_off + 4
machine, num_sections = struct.unpack_from('<HH', data, coff_off)
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
magic = struct.unpack_from('<H', data, opt_off)[0]
is_pe32plus = (magic == 0x20b)

if is_pe32plus:
    data_dir_off = opt_off + 112
else:
    data_dir_off = opt_off + 96

export_rva, export_size = struct.unpack_from('<II', data, data_dir_off)
print(f"Machine: {hex(machine)} PE32+={is_pe32plus} ExportTableRVA={hex(export_rva)} size={export_size}")

# section headers to map RVA->file offset
sec_off = opt_off + opt_hdr_size
sections = []
for i in range(num_sections):
    entry = data[sec_off+i*40 : sec_off+(i+1)*40]
    name = entry[0:8].rstrip(b'\x00').decode('latin1')
    vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', entry, 8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))

def rva_to_off(rva):
    for name, vaddr, vsize, rawptr, rawsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rawptr + (rva - vaddr)
    return None

print("Sections:", [(n, hex(v)) for n,v,*_ in sections])

exp_off = rva_to_off(export_rva)
if exp_off is None:
    print("Could not map export RVA"); sys.exit(1)

(chars, ts, maj, minr, name_rva, ordbase, naddr, nnames, addr_tbl_rva, name_tbl_rva, ord_tbl_rva) = struct.unpack_from('<IIHHIIIIIII', data, exp_off)
dll_name_off = rva_to_off(name_rva)
dll_name = data[dll_name_off:data.index(b'\x00', dll_name_off)].decode('latin1')
print(f"DLL name: {dll_name}  NumberOfFunctions={naddr} NumberOfNames={nnames}")

name_tbl_off = rva_to_off(name_tbl_rva)
names = []
for i in range(nnames):
    name_rva_i = struct.unpack_from('<I', data, name_tbl_off + i*4)[0]
    noff = rva_to_off(name_rva_i)
    end = data.index(b'\x00', noff)
    names.append(data[noff:end].decode('latin1'))

print(f"\n=== {len(names)} exported names ===")
for n in sorted(names):
    print(n)
