import idaapi
import idc
import idautils

def find_xpc_type_confusion():
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if "xpc_" in func_name:  # Filter functions with XPC prefix
            for block_ea in idautils.FuncItems(func_ea):
                for head in idautils.Heads(block_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
                    mnem = idc.print_insn_mnem(head)
                    if mnem == "bl" or mnem == "blx":  # Check for function calls
                        target = idc.get_operand_value(head, 0)
                        target_name = idc.get_func_name(target)
                        if "xpc_" in target_name:  # Filter functions with XPC prefix
                            args = idc.get_arg_addrs(head)
                            if args:
                                # Check argument types for potential type confusion
                                for arg_ea in args:
                                    arg_type = idc.print_operand(arg_ea, 1)
                                    if "CFTypeRef" in arg_type or "xpc_" in arg_type:
                                        print(f"Potential XPC Type Confusion at {hex(head)} in function {func_name}")

def main():
    find_xpc_type_confusion()

if __name__ == "__main__":
    main()
