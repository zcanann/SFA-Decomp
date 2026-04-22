/*
 * Target bytes at this split are not TRK DebuggerDriver code. The 6 funcs
 * here are game-side state-machine handlers: ddh_cc_initinterrupts is a
 * large branch table on a u8 state (r31->0xa8c), dispatching through a
 * vtable-like sbss pointer (lbl_803DD70C). fn_802BB648 is a float helper
 * that calls fn_80038498/fn_800383E8 and a bss param block (lbl_803DBD50).
 * fn_802BB718 is empty (blr). fn_802BB71C returns 0. fn_802BB724/754 are
 * tiny float/int store helpers. Asm-only to preserve the exact byte image.
 */

extern int fn_800201AC(int a, int b);
extern int fn_80038498(void* a, int b);
extern int fn_800383E8(void);
extern void fn_80021FAC(void* a, void* b);
extern void fn_800223A8(void* a, int b, void* c);
extern void fn_8003BA48(void* a);

extern void _savegpr_25(void);
extern void _restgpr_25(void);

__declspec(section ".sdata") extern int lbl_803DD70C;
__declspec(section ".sdata") extern int lbl_803DD728;
extern char lbl_803DBD50[];

__declspec(section ".sdata2") extern const float lbl_803E8ECC;
__declspec(section ".sdata2") extern const float lbl_803E8F14;

asm int ddh_cc_initinterrupts(void* a, void* b, void* c) {
    nofralloc
    stwu r1, -0x20(r1)
    mflr r0
    stw r0, 0x24(r1)
    stw r31, 0x1c(r1)
    stw r30, 0x18(r1)
    stw r29, 0x14(r1)
    stw r28, 0x10(r1)
    mr r29, r3
    mr r30, r5
    lwz r31, 0xb8(r29)
    lbz r0, 0xaf(r29)
    ori r0, r0, 0x8
    clrlwi r0, r0, 24
    stb r0, 0xaf(r29)
    lbz r0, 0xa8c(r31)
    cmpwi r0, 0x3
    beq _di_3
    bge _di_hi
    cmpwi r0, 0x1
    beq _di_1
    bge _di_end
    cmpwi r0, 0x0
    bge _di_0
    b _di_end
_di_hi:
    cmpwi r0, 0x5
    beq _di_5
    bge _di_end
    b _di_4
_di_0:
    li r0, 0x0
    stb r0, 0x56(r30)
    lha r0, 0xb4(r29)
    cmpwi r0, -0x1
    bne _di_0b
    li r28, 0x0
    b _di_0c
_di_0a:
    li r3, 0x17b
    li r4, 0x1
    bl fn_800201AC
    lbz r0, 0xa8e(r31)
    ori r0, r0, 0x20
    clrlwi r0, r0, 24
    stb r0, 0xa8e(r31)
    addi r28, r28, 0x1
_di_0c:
    lbz r0, 0x8b(r30)
    cmpw r28, r0
    blt _di_0a
_di_0b:
    mr r3, r29
    mr r4, r31
    li r5, 0x1
    lwz r6, lbl_803DD70C(r0)
    lwz r6, 0x0(r6)
    lwz r12, 0x14(r6)
    mtctr r12
    bctrl
    b _di_end
_di_5:
    li r0, 0x0
    stb r0, 0x56(r30)
    mr r4, r31
    li r5, 0x2
    lwz r6, lbl_803DD70C(r0)
    lwz r6, 0x0(r6)
    lwz r12, 0x14(r6)
    mtctr r12
    bctrl
    b _di_end
_di_4:
    li r0, 0x0
    stb r0, 0x56(r30)
    mr r4, r31
    li r5, 0x7
    lwz r6, lbl_803DD70C(r0)
    lwz r6, 0x0(r6)
    lwz r12, 0x14(r6)
    mtctr r12
    bctrl
    b _di_end
_di_1:
    li r0, 0x0
    stb r0, 0x56(r30)
    lha r0, 0xb4(r29)
    cmpwi r0, -0x1
    beq _di_1a
    lbz r0, 0xa8d(r31)
    cmpwi r0, 0x4
    beq _di_1b
    bge _di_1b
    cmpwi r0, 0x0
    bge _di_1c
    b _di_1b
_di_1c:
    li r5, 0x6
    b _di_1d
_di_1b:
    li r5, 0x7
    b _di_1d
_di_1a:
    li r5, 0x7
_di_1d:
    mr r3, r29
    mr r4, r31
    lwz r6, lbl_803DD70C(r0)
    lwz r6, 0x0(r6)
    lwz r12, 0x14(r6)
    mtctr r12
    bctrl
    b _di_end
_di_3:
    li r0, 0x0
    stb r0, 0x56(r30)
    li r0, 0x1
    stb r0, 0x27a(r31)
    mr r4, r31
    li r5, 0x7
    lwz r6, lbl_803DD70C(r0)
    lwz r6, 0x0(r6)
    lwz r12, 0x14(r6)
    mtctr r12
    bctrl
_di_end:
    mr r3, r29
    addi r4, r31, 0x4
    lwz r5, lbl_803DD728(r0)
    lwz r5, 0x0(r5)
    lwz r12, 0x20(r5)
    mtctr r12
    bctrl
    lfs f0, lbl_803E8ECC(r0)
    stfs f0, 0x294(r31)
    stfs f0, 0x284(r31)
    stfs f0, 0x280(r31)
    stfs f0, 0x24(r29)
    stfs f0, 0x28(r29)
    stfs f0, 0x2c(r29)
    lbz r0, 0x56(r30)
    extsb r3, r0
    neg r0, r3
    or r0, r0, r3
    srwi r3, r0, 31
    lwz r31, 0x1c(r1)
    lwz r30, 0x18(r1)
    lwz r29, 0x14(r1)
    lwz r28, 0x10(r1)
    lwz r0, 0x24(r1)
    mtlr r0
    addi r1, r1, 0x20
    blr
}

asm void fn_802BB648(void* obj, float x) {
    nofralloc
    stwu r1, -0x50(r1)
    mflr r0
    stw r0, 0x54(r1)
    stfd f31, 0x40(r1)
    psq_st f31, 0x48(r1), 0, 0
    stw r31, 0x3c(r1)
    stw r30, 0x38(r1)
    mr r30, r3
    fmr f31, f1
    li r4, 0x1
    bl fn_80038498
    mr r31, r3
    mr r3, r30
    li r4, 0x1
    addi r5, r1, 0x10
    addi r6, r1, 0xc
    addi r7, r1, 0x8
    bl fn_800383E8
    lfs f0, 0x10(r1)
    stfs f0, 0x20(r1)
    lfs f0, 0xc(r1)
    stfs f0, 0x24(r1)
    lfs f0, 0x8(r1)
    stfs f0, 0x28(r1)
    li r0, 0x0
    sth r0, 0x14(r1)
    sth r0, 0x16(r1)
    sth r0, 0x18(r1)
    lwz r3, 0x50(r30)
    lfs f0, 0x4(r3)
    fdivs f0, f31, f0
    stfs f0, 0x1c(r1)
    lis r3, lbl_803DBD50@ha
    addi r3, r3, lbl_803DBD50@l
    addi r4, r1, 0x14
    bl fn_80021FAC
    lis r3, lbl_803DBD50@ha
    addi r3, r3, lbl_803DBD50@l
    mr r4, r31
    mr r5, r3
    bl fn_800223A8
    lis r3, lbl_803DBD50@ha
    addi r3, r3, lbl_803DBD50@l
    bl fn_8003BA48
    psq_l f31, 0x48(r1), 0, 0
    lfd f31, 0x40(r1)
    lwz r31, 0x3c(r1)
    lwz r30, 0x38(r1)
    lwz r0, 0x54(r1)
    mtlr r0
    addi r1, r1, 0x50
    blr
}

void fn_802BB718(void) {
}

int fn_802BB71C(void) {
    return 0;
}

asm void fn_802BB724(void* a, float* out) {
    nofralloc
    lwz r3, 0xb8(r3)
    lha r0, 0x274(r3)
    cmpwi r0, 0xa
    bne _f724_0
    lfs f0, 0x2a0(r3)
    fneg f0, f0
    stfs f0, 0x0(r4)
    b _f724_1
_f724_0:
    lfs f0, lbl_803E8F14(r0)
    stfs f0, 0x0(r4)
_f724_1:
    lfs f1, lbl_803E8ECC(r0)
    blr
}

#pragma scheduling off
void fn_802BB754(void* a, float* out, int* flag) {
    *out = lbl_803E8ECC;
    *flag = 0;
}
#pragma scheduling reset
