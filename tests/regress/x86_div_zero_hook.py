import regress
from unicorn import Uc, UC_ARCH_X86, UC_HOOK_INTR, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP


CODE = (
    b"\x31\xc0"      # xor eax, eax
    b"\xf7\xf0"      # div eax
    b"\xf7\xf0"      # div eax
    b"\xf7\xf0"      # div eax
    b"\x90"            # nop
)
CODE_ADDR = 0x100000
DIV_ZERO_EXCEPTION = 0
DIV_EAX_SIZE = 2


class X86DivZeroHook(regress.RegressTest):

    def test_div_zero_hook_clears_exception_state(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(CODE_ADDR, 0x1000)
        uc.mem_write(CODE_ADDR, CODE)

        exceptions = []

        def hook_intr(uc, intno, user_data):
            exceptions.append(intno)
            eip = uc.reg_read(UC_X86_REG_EIP)
            uc.reg_write(UC_X86_REG_EIP, eip + DIV_EAX_SIZE)

        uc.hook_add(UC_HOOK_INTR, hook_intr)
        uc.emu_start(CODE_ADDR, CODE_ADDR + len(CODE))

        self.assertEqual([DIV_ZERO_EXCEPTION] * 3, exceptions)
        self.assertEqual(CODE_ADDR + len(CODE), uc.reg_read(UC_X86_REG_EIP))


if __name__ == "__main__":
    regress.main()
