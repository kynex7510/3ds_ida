"""
Create IPS file from database patches.
- Kynex7510
"""

from plugin_utility import IDAUtils, Logger

import ida_bytes

IPS_HEADER = [0x50, 0x41, 0x54, 0x43, 0x48]
IPS_FOOTER = [0x45, 0x4F, 0x46]

LOGGER = Logger("make_ips_patch.py")

patches_dict = {}
last_patch_offset = 0
last_patch_size = 0

def add_footer(buffer: list):
    buffer.extend(IPS_FOOTER)

def add_patch(buffer: list, offset: int, patch_data: list):
    size = len(patch_data)

    if offset > 0xFFFFFF:
        raise Exception(f"Offset \"{hex(offset)}\" is too large")

    if size > 0xFFFF:
        raise Exception(f"Size of \"{size}\" for offset \"{hex(offset)}\" is too large")
    
    buffer.extend(offset.to_bytes(length=3, byteorder='big'))
    buffer.extend(size.to_bytes(length=2, byteorder='big'))
    buffer.extend(patch_data)

def visitor(ea, fpos, org_val, patch_val):
    global patches_dict
    global last_patch_offset
    global last_patch_size

    if ea == last_patch_offset + last_patch_size:
        patches_dict[last_patch_offset].append(patch_val)
        last_patch_size += 1
    else:
        patches_dict[ea] = [patch_val]
        last_patch_offset = ea
        last_patch_size = 1

    return 0

if __name__ == "__main__":
    map_base = IDAUtils.map_base()
    file_size = IDAUtils.file_size()

    # Get patches.
    patches_dict.clear()
    ida_bytes.visit_patched_bytes(map_base, map_base + file_size, visitor)

    # Build patch file.
    has_patches = False
    patch = IPS_HEADER

    for ea in patches_dict:
        has_patches = True
        data = patches_dict[ea]
        offset = ea - map_base

        # Handle the case when the offset is the same as the footer.
        if offset == 0x454F46:
            offset -= 1
            data.insert(0, ida_bytes.get_byte(offset))
        
        add_patch(patch, offset, data)

    add_footer(patch)

    # Write patch file.
    if has_patches:
        path = IDAUtils.ask_file(True, "Select where to save the IPS file", "patch.ips")
        with open(path, "wb") as ips:
            ips.write(bytes(patch))
        LOGGER.log(f"Patch saved at \"{path}\"")
    else:
        LOGGER.log("No patches. Nothing to do.")