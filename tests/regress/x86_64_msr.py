import regress
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x40000
CODE_SIZE = 0x1000

SCRATCH_ADDR = 0x80000
SCRATCH_SIZE = 0x1000

SEGMENT_ADDR = 0x5000
SEGMENT_SIZE = 0x1000

FSMSR = 0xC0000100
GSMSR = 0xC0000101
TSC_AUX_MSR = 0xC0000103

MSR_REGS_64 = (UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_RIP)
MSR_REGS_32 = (UC_X86_REG_EAX, UC_X86_REG_EDX, UC_X86_REG_ECX, UC_X86_REG_EIP)


def set_msr(uc, msr, value, scratch=SCRATCH_ADDR, regs=MSR_REGS_64):
    """
    set the given model-specific register (MSR) to the given value.
    this will clobber some memory at the given scratch address, as it emits some code.
    """
    reg_ax, reg_dx, reg_cx, reg_ip = regs

    # save clobbered registers
    oax = uc.reg_read(reg_ax)
    odx = uc.reg_read(reg_dx)
    ocx = uc.reg_read(reg_cx)
    oip = uc.reg_read(reg_ip)

    # x86: wrmsr
    buf = b'\x0f\x30'
    uc.mem_write(scratch, buf)
    uc.reg_write(reg_ax, value & 0xFFFFFFFF)
    uc.reg_write(reg_dx, (value >> 32) & 0xFFFFFFFF)
    uc.reg_write(reg_cx, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch + len(buf), count=1)

    # restore clobbered registers
    uc.reg_write(reg_ax, oax)
    uc.reg_write(reg_dx, odx)
    uc.reg_write(reg_cx, ocx)
    uc.reg_write(reg_ip, oip)


def get_msr(uc, msr, scratch=SCRATCH_ADDR, regs=MSR_REGS_64):
    """
    fetch the contents of the given model-specific register (MSR).
    this will clobber some memory at the given scratch address, as it emits some code.
    """
    reg_ax, reg_dx, reg_cx, reg_ip = regs

    # save clobbered registers
    oax = uc.reg_read(reg_ax)
    odx = uc.reg_read(reg_dx)
    ocx = uc.reg_read(reg_cx)
    oip = uc.reg_read(reg_ip)

    # x86: rdmsr
    buf = b'\x0f\x32'
    uc.mem_write(scratch, buf)
    uc.reg_write(reg_cx, msr & 0xFFFFFFFF)
    uc.emu_start(scratch, scratch + len(buf), count=1)
    eax = uc.reg_read(UC_X86_REG_EAX)
    edx = uc.reg_read(UC_X86_REG_EDX)

    # restore clobbered registers
    uc.reg_write(reg_ax, oax)
    uc.reg_write(reg_dx, odx)
    uc.reg_write(reg_cx, ocx)
    uc.reg_write(reg_ip, oip)

    return (edx << 32) | (eax & 0xFFFFFFFF)


def set_gs(uc, addr):
    """
    set the GS.base hidden descriptor-register field to the given address.
    this enables referencing the gs segment on x86-64.
    """
    return set_msr(uc, GSMSR, addr)


def get_gs(uc):
    """
    fetch the GS.base hidden descriptor-register field.
    """
    return get_msr(uc, GSMSR)


def set_fs(uc, addr):
    """
    set the FS.base hidden descriptor-register field to the given address.
    this enables referencing the fs segment on x86-64.
    """
    return set_msr(uc, FSMSR, addr)


def get_fs(uc):
    """
    fetch the FS.base hidden descriptor-register field.
    """
    return get_msr(uc, FSMSR)


class TestGetSetMSR(regress.RegressTest):
    def test_tsc_aux_msr_32(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        value = 0x1234567887654321
        set_msr(uc, TSC_AUX_MSR, value, regs=MSR_REGS_32)
        self.assertEqual(value, get_msr(uc, TSC_AUX_MSR, regs=MSR_REGS_32))

    def test_msr(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        set_msr(uc, FSMSR, 0x1000)
        self.assertEqual(0x1000, get_msr(uc, FSMSR))

        set_msr(uc, GSMSR, 0x2000)
        self.assertEqual(0x2000, get_msr(uc, GSMSR))

    def test_gs(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
        uc.mem_map(CODE_ADDR, CODE_SIZE)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        code = b'\x65\x48\x33\x0C\x25\x18\x00\x00\x00'  # xor rcx, qword ptr gs:[0x18]
        uc.mem_write(CODE_ADDR, code)
        uc.mem_write(SEGMENT_ADDR + 0x18, b'AAAAAAAA')

        set_gs(uc, SEGMENT_ADDR)
        self.assertEqual(SEGMENT_ADDR, get_gs(uc))

        uc.emu_start(CODE_ADDR, CODE_ADDR + len(code))

        self.assertEqual(uc.reg_read(UC_X86_REG_RCX), 0x4141414141414141)

    def test_fs(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)

        uc.mem_map(SEGMENT_ADDR, SEGMENT_SIZE)
        uc.mem_map(CODE_ADDR, CODE_SIZE)
        uc.mem_map(SCRATCH_ADDR, SCRATCH_SIZE)

        code = b'\x64\x48\x33\x0C\x25\x18\x00\x00\x00'  # xor rcx, qword ptr fs:[0x18]
        uc.mem_write(CODE_ADDR, code)
        uc.mem_write(SEGMENT_ADDR + 0x18, b'AAAAAAAA')

        set_fs(uc, SEGMENT_ADDR)
        self.assertEqual(SEGMENT_ADDR, get_fs(uc))

        uc.emu_start(CODE_ADDR, CODE_ADDR + len(code))

        self.assertEqual(uc.reg_read(UC_X86_REG_RCX), 0x4141414141414141)


if __name__ == '__main__':
    regress.main()
