#include "PowerPC_EABI_Support/Runtime/ptmf.h"

asm long __ptmf_test(register __ptmf* ptmf) {
    // clang-format off
    nofralloc

    lwz r5, __ptmf.this_delta(r3)
    lwz r6, __ptmf.v_offset(r3)
    lwz r7, __ptmf.f_data(r3)
    li r3, 1
    cmpwi r5, 0
    cmpwi cr6, r6, 0
    cmpwi cr7, r7, 0
    bnelr
    bnelr cr6
    bnelr cr7
    li r3, 0
    blr
    // clang-format on
}

asm void __ptmf_scall(...) {
    // clang-format off
    nofralloc

    lwz r0, 0(r12)
    lwz r11, 4(r12)
    lwz r12, 8(r12)
    add r3, r3, r0
    cmpwi r11, 0
    blt lbl_803620A4

    lwzx r12, r3, r12
    lwzx r12, r12, r11

lbl_803620A4:
    mtctr r12
    bctr
    // clang-format on
}
