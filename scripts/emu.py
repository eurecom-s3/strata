from unicorn import *
from unicorn.x86_const import *

def to_canonical_address(addr):
    return addr | 0xffff000000000000

def to_volatility_address(addr):
    return addr & 0xffffffffffff

class Emulator:
    def __init__(self, panda, volatility, debug):
        self.panda = panda
        self.volatility = volatility
        self.ksize_addr = to_canonical_address(self.volatility.get_symbol("__ksize").address)
        self.find_vm_area_addr = to_canonical_address(self.volatility.get_symbol("find_vm_area").address)
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.debug = debug
        cpu = panda.get_cpu()
        
        # Define stack
        self.stack = 0xffffffeeffff0000 # Unused hole in the memory layout
        self.stack_size = 0x100000
        self.mu.mem_map(self.stack - self.stack_size, self.stack_size)

        # Map ksize function
        self.mu.mem_map(self.ksize_addr >> 12 << 12, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        self.mu.mem_write(self.ksize_addr >> 12 << 12, self.panda.virtual_memory_read(cpu, self.ksize_addr >> 12 << 12, 0x1000))

        # Map page_offset_base area
        page_offset_base_addr = to_canonical_address(volatility.get_symbol("page_offset_base").address)
        self.mu.mem_map(page_offset_base_addr >> 12 << 12, 0x1000, UC_PROT_READ )
        self.mu.mem_write(page_offset_base_addr >> 12 << 12, self.panda.virtual_memory_read(cpu, page_offset_base_addr >> 12 << 12, 0x1000))

        # Map find_vm_area function
        self.mu.mem_map(self.find_vm_area_addr >> 12 << 12, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        self.mu.mem_write(self.find_vm_area_addr >> 12 << 12, self.panda.virtual_memory_read(cpu, self.find_vm_area_addr >> 12 << 12, 0x1000))

        # Map patch raw_spin_lock/unlock
        raw_spin_lock_addr = to_canonical_address(self.volatility.get_symbol("_raw_spin_lock").address)
        raw_spin_unlock_addr = to_canonical_address(self.volatility.get_symbol("_raw_spin_unlock").address)
        self.mu.mem_map(raw_spin_lock_addr >> 12 << 12, 0x1000, UC_PROT_READ | UC_PROT_EXEC) # They are in the same page!
        self.mu.mem_write(raw_spin_lock_addr, b"\xc3")
        self.mu.mem_write(raw_spin_unlock_addr, b"\xc3")

        # Add hooks
        self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.map_region)
        # if self.debug:
        #     self.mu.hook_add(UC_HOOK_CODE, self.print_instructions)

        # Reset the emulator
        self.reset_emulator()

    def reset_emulator(self):
        # Stack init
        self.mu.mem_write(self.stack - self.stack_size, b"\x00" * self.stack_size)
        self.mu.reg_write(UC_X86_REG_RSP, self.stack)
        self.mu.reg_write(UC_X86_REG_RBP, self.stack)

        # GS init
        try:
            self.mu.reg_write(UC_X86_REG_GS, 0x1000)
        except UcError:
            pass

        # Remove regions RW (data)
        for start, end, perm in self.mu.mem_regions():
            if perm == UC_PROT_READ | UC_PROT_WRITE:
                self.mu.mem_unmap(start, end - start + 1)

    def print_instructions(self, uc, address, size, user_data):
        print(hex(address))

    def map_region(self, uc, access, address, size, value, user_data):
        # Add a memory region

        # Last RET
        if address == 0xffffffeeffff0000:
            # if self.debug:
            #     print("STOP")
            uc.emu_stop()
            return True

        # Invalid address
        if address < 0xffff000000000000:
            # print(f"ERROR Emulator try to access invalid error {hex(address)}")
            raise UcError

        try:
            if access == UC_HOOK_MEM_FETCH_UNMAPPED:
                perms = UC_PROT_READ | UC_PROT_EXEC
                # if self.debug:
                    # print("EXEC", hex(uc.reg_read(UC_X86_REG_RIP)), hex(address))
            else:
                perms = UC_PROT_READ | UC_PROT_WRITE
                # if self.debug:
                    # print("READ/WRITE", hex(uc.reg_read(UC_X86_REG_RIP)), hex(address))
            
            uc.mem_map(address >> 12 << 12, 0x1000, perms)
            uc.mem_write(address >> 12 << 12, self.panda.virtual_memory_read(self.panda.get_cpu(), address >> 12 << 12 , 0x1000))

        except Exception as ex:
            print(f"ERROR adding region {hex(address >> 12 << 12)} to unicorn {ex}")
            return False
        return True

    def emu_ksize(self, address):
        self.reset_emulator()

        self.mu.reg_write(UC_X86_REG_RDI, address)
        try:
            self.mu.emu_start(self.ksize_addr, self.ksize_addr + 0x1000)
        except Exception as ex:
            pass

        return self.mu.reg_read(UC_X86_REG_RAX)

    def emu_find_vm_area(self, address):
        self.reset_emulator()

        self.mu.reg_write(UC_X86_REG_RDI, address)
        # print("#######")
        try:
            self.mu.emu_start(self.find_vm_area_addr, self.find_vm_area_addr + 0x1000)
        except Exception as ex:
            pass

        print(hex(self.mu.reg_read(UC_X86_REG_RAX)))
        vm_struct = self.volatility.object("vm_struct", to_volatility_address(self.mu.reg_read(UC_X86_REG_RAX)))
        if not (vm_struct.flags & 0x00000040):
            return vm_struct.size - 0x1000
        else:
            return vm_struct.size

        
    