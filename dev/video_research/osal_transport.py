"""Pinned original OSAL transport metadata; never execute imports or device I/O."""
from __future__ import annotations
import hashlib
from request_trace import Elf64, check_image, span
from ap_xrefs import imported_slots

SIZE = 43752
SHA = '09ebf5980237fc473077dc844763dcb00cba423f431646e3be7c0ca49ea70ff3'
FUNCTIONS = {'osal_snd_msg':(0x5e60,684), 'u_osal_snd_msg':(0x3a10,136),
             'osal_set_msg_src':(0x7e20,8), 'osal_valloc_msg_wait':(0x67b0,448),
             'u_osal_valloc_msg_wait':(0x3e98,144)}


def inspect(data: bytes) -> dict:
    check_image(data,SIZE,SHA,'original libosal_uipc.so')
    elf=Elf64(data)
    functions=[]
    for symbol in elf.symbols():
        if symbol['name'] not in FUNCTIONS:
            continue
        va,size=FUNCTIONS[symbol['name']]
        if (symbol['va'],symbol['size'],symbol['type']) != (va,size,2):
            raise ValueError('OSAL exported function differs.')
        off=elf.file_offset(va,size)
        functions.append(dict(name=symbol['name'],va=hex(va),file_offset=hex(off),
            size=size,sha256=hashlib.sha256(span(data,off,size)).hexdigest()))
    if len(functions)!=len(FUNCTIONS):
        raise ValueError('Missing/duplicate OSAL exports.')
    imports=imported_slots(elf,{0x1a018,0x1a128,0x1a1c8})
    actual={int(item['slot'],16):item['name'] for item in imports}
    if actual != {0x1a018:'u_osal_snd_msg',0x1a128:'ioctl',0x1a1c8:'u_osal_valloc_msg_wait'}:
        raise ValueError('OSAL transport imports differ.')
    return dict(schema='a7c2-osal-transport-boundary/1',component_sha256=SHA,
        functions=functions,imports=imports,
        reviewed_static_path=dict(routing_candidate='0x90030001',bit15=0,
            osal_branch='0x5eb8',external_path='0x6050',
            u_osal_ioctl_call='0x3a48',ioctl_plt='0x2530',
            ioctl_request_low32='0x80000004',
            descriptor_source='runtime global, not resolved',
            runtime_symbol_binding_verified=False),
        source_metadata_offset=-12,source_metadata_width=4,
        source_metadata_semantics='osal_set_msg_src stores w1 at message pointer minus 12',
        message_delivery_verified=False,kernel_routing_verified=False,
        movie_path_verified=False,recording_verified=False,firmware_executed=False,
        camera_io=False,installable=False)
