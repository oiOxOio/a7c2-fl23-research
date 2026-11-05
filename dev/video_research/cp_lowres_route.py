"""Bounded low-resolution candidate routing, not a recording/unlock path."""
from __future__ import annotations
import hashlib
from request_trace import CP_SIZE,CP_SHA,check_image,cp_span


def inspect(cp:bytes)->dict:
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    ranges=((0xb2a87c,0xb2a906),(0x4c09b0,0x4c09bc),(0x4c0ae8,0x4c0b20),
        (0x4c0b46,0x4c0b50),(0x4c0c30,0x4c0c4a),(0x4c0cca,0x4c0d4e),
        (0x4cc0a0,0x4cc0b8),(0x4cc21c,0x4cc24a),(0x4cd20c,0x4cd224),(0x4cd394,0x4cd3c2),
        (0xb29ec8,0xb29fca),(0xb2a04c,0xb2a17c))
    return dict(schema='a7c2-cp-lowres-route-static/1',cp_sha256=CP_SHA,
        candidate='0x5002',candidate_geometry='3504x2336, not native 3840-wide samples',
        selection=dict(entry='0xb2a87c',checks='0xb2a8cc -> 0x989e8a availability; if second argument == 1, also 0xb0b196',
            preference='5002 then 5020 then 5000; nonzero size flag queries 5004/5021 before final conversion',
            actual_availability_or_policy_verified=False),
        reviewed_routes=['0x4c09b6 -> 0x4c0b46 -> 0x4c0c44 -> 0xb29e9a',
            '0x4c0aec -> 0x4c0b12 -> 0x4c0cda -> 0x4c0cde -> 0xb29e9a'],
        classification='5002/5004 do not match the 5200/5201,5220/5221,5400/5401,5420/5421 category; 0xb29f70 branch',
        rate_gate='0xb29f72 tests selector+0x3b4; value 1 diagnoses instead of building. Other values continue.',
        callback_binding='0xb29f90..0xb29fc4 selects 0x4cc0a1 or 0x4cd20d according to prior helper-derived fp; not 0x4c79c1',
        shared_sync_submission=dict(first='4cc0b0 reads owner[0]; 4cc222/4cc240 forwards it through b28c5c to callback 4ce7bc',
            second='4cd21c reads owner[0]; 4cd39a/4cd3b8 forwards it through b28c5c to callback 4ce7bc',
            scheduler_state='both call b28a88 with 0; reviewed 4c79c0 route calls it with 2',
            not_evidence_of_no_submission=True,live_scheduler_or_recording_verified=False),
        later_override='0x4c0cfc selects 4c79c1 AND mode 9000; 0x4c0d32 selects 4c79c1 AND mode b20. Neither preserves candidate 5002.',
        all_possible_routes_exhausted=False,live_movie_recording_route_proven=False,
        physical_field_of_view_verified=False,physical_cadence_verified=False,
        ranges=[dict(start=hex(lo),end=hex(hi),sha256=hashlib.sha256(cp_span(cp,lo,hi-lo)).hexdigest()) for lo,hi in ranges],
        camera_io=False,installable=False)


def run_original(cp:bytes)->dict:
    """Original classification/converter/binding; declared callback-policy inputs.

    Stops before the final record builder. Earlier availability checks, helper
    policy, caller state, scheduling and later override gates are not executed.
    """
    check_image(cp,CP_SIZE,CP_SHA,'CP')
    import unicorn as u
    from unicorn import arm_const as a
    cases=[]
    for flag in (0,1):
        for policy in (0,1):
            uc=u.Uc(u.UC_ARCH_ARM,u.UC_MODE_THUMB)
            ranges=((0xb29ecc,0xb29ef8),(0xb29f88,0xb29fc6),(0xb29f60,0xb29f64),(0xb2a04c,0xb2a17c))
            for page in (0xb29000,0xb2a000):
                uc.mem_map(page,4096,u.UC_PROT_READ|u.UC_PROT_EXEC);uc.mem_write(page,cp_span(cp,page,4096))
            sp=0x20000800;uc.mem_map(0x20000000,4096,u.UC_PROT_READ|u.UC_PROT_WRITE)
            uc.reg_write(a.UC_ARM_REG_SP,sp);uc.reg_write(a.UC_ARM_REG_R4,0x5002)
            trace=[];phase=[0];stops=[]
            def code(em,pc,size,_):
                target=0xb29f70 if phase[0]==0 else 0xb29f64
                if pc==target:stops.append(pc);em.emu_stop();return
                if not any(lo<=pc and pc+size<=hi for lo,hi in ranges):raise ValueError('Unreviewed lowres instruction.')
                if not em.reg_read(a.UC_ARM_REG_CPSR)&32:raise ValueError('Lowres fragment left Thumb.')
                trace.append((pc,size))
            def memory(em,access,addr,size,value,_):
                if access!=u.UC_MEM_WRITE or not sp<=addr or addr+size>sp+20:raise ValueError('Unexpected lowres memory access.')
            uc.hook_add(u.UC_HOOK_CODE,code);uc.hook_add(u.UC_HOOK_MEM_READ|u.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(0xb29ecd,0,count=100,timeout=1_000_000)
            if stops!=[0xb29f70]:raise ValueError('Lowres classification differs.')
            phase[0]=1
            for reg,value in ((a.UC_ARM_REG_R6,flag),(a.UC_ARM_REG_R11,policy),(a.UC_ARM_REG_R10,0x21000000),(a.UC_ARM_REG_R8,0),(a.UC_ARM_REG_R9,0)):
                uc.reg_write(reg,value)
            uc.emu_start(0xb29f89,0,count=150,timeout=1_000_000)
            mode=uc.reg_read(a.UC_ARM_REG_R0);callback=uc.reg_read(a.UC_ARM_REG_R3)
            if stops[-1:]!=[0xb29f64] or mode!=(0x5002 if flag==0 else 0x5004) or callback!=(0x4cd20d if policy==0 else 0x4cc0a1):raise ValueError('Lowres callback binding differs.')
            cases.append(dict(declared_size_flag=flag,declared_helper_policy=policy,mode=hex(mode),callback=hex(callback),
                instructions=len(trace),instruction_stream_sha256=hashlib.sha256(b''.join(cp_span(cp,pc,size) for pc,size in trace)).hexdigest()))
    return dict(schema='a7c2-cp-lowres-route-original/1',cp_sha256=CP_SHA,cases=cases,
        fragments_executed_separately=True,rate_gate_executed=False,availability_executed=False,
        helper_policy_executed=False,record_builder_executed=False,later_override_executed=False,
        camera_io=False,installable=False)
