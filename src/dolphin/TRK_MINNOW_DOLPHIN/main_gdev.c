/*
 * Target bytes at this split are not TRK/Gdev console code. The 7 funcs
 * here are game-side helpers that poke at an object at r3+0xB8 and call
 * a bunch of game-side fn_800X helpers (not TRK ones). gdev_cc_initinterrupts
 * tests a byte and returns 1 or 2; fn_802BB8E4 branches on a 5-way state
 * compare; fn_802BB998 is a longer loop over some count with float math;
 * fn_802BBAEC/AF4 just return 0xD0C / 0x43; fn_802BBAFC calls fn_8003709C;
 * fn_802BBB20 is a multi-step setup calling fn_8003B9EC/fn_80038524/etc.
 * Asm-only to preserve the exact byte image.
 */

extern void fn_80036F50(void);
extern int fn_80014B68(int a, int b);
extern int fn_8006EEA0(int a, int b);
extern void fn_8000BB38(void);
extern void fn_80014ACC(void);
extern int fn_80022264(int a, int b);
extern void fn_8003B9EC(float x);
extern void fn_80038524(void);
extern void fn_80038378(void);
extern void fn_8003709C(void* a, int b);

extern void _savegpr_25(void);
extern void _restgpr_25(void);

__declspec(section ".sdata") extern int lbl_803DD708;

__declspec(section ".sdata2") extern const float lbl_803E8ED8;
__declspec(section ".sdata2") extern const float lbl_803E8EDC;
__declspec(section ".sdata2") extern const float lbl_803E8EF0;
__declspec(section ".sdata2") extern const float lbl_803E8F38;

asm int gdev_cc_initinterrupts(void* obj) {
    nofralloc
    lwz r3, 0xb8(r3)
    lbz r0, 0xa90(r3)
    cmplwi r0, 0x0
    beq _gi_0
    li r3, 0x1
    blr
_gi_0:
    li r3, 0x2
    blr
}

asm int fn_802BB8E4(void* arg0) {
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    mr r4, r3
    lwz r3, 0xb8(r4)
    lfs f0, lbl_803E8ED8(r0)
    stfs f0, 0x8(r1)
    lbz r0, 0xa8c(r3)
    cmpwi r0, 0x5
    beq _f8e_0
    bge _f8e_1
    cmpwi r0, 0x0
    beq _f8e_0
    b _f8e_1
_f8e_0:
    li r3, 0x0
    b _f8e_end
_f8e_1:
    lha r0, 0x274(r3)
    cmpwi r0, 0x7
    beq _f8e_2
    li r3, 0x0
    b _f8e_end
_f8e_2:
    lwz r0, 0xc0(r4)
    cmplwi r0, 0x0
    beq _f8e_3
    li r3, 0x0
    b _f8e_end
_f8e_3:
    li r3, 0x13
    addi r5, r1, 0x8
    bl fn_80036F50
    cmplwi r3, 0x0
    beq _f8e_4
    lbz r0, 0xaf(r3)
    rlwinm r0, r0, 0, 29, 29
    cmpwi r0, 0x0
    beq _f8e_4
    li r3, 0x0
    li r4, 0x100
    bl fn_80014B68
    li r3, 0x1
    b _f8e_end
_f8e_4:
    li r3, 0x0
_f8e_end:
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
}

asm void fn_802BB998(void* a, void* b, void* c) {
    nofralloc
    stwu r1, -0x40(r1)
    mflr r0
    stw r0, 0x44(r1)
    addi r11, r1, 0x40
    bl _savegpr_25
    mr r27, r3
    mr r28, r4
    mr r29, r5
    li r31, 0x0
    lwz r3, 0x314(r29)
    rlwinm r0, r3, 0, 30, 30
    cmpwi r0, 0x0
    beq _fb9_0
    ori r0, r31, 0x1
    clrlwi r31, r0, 24
_fb9_0:
    rlwinm r0, r3, 0, 29, 29
    cmpwi r0, 0x0
    beq _fb9_1
    ori r0, r31, 0x2
    clrlwi r31, r0, 24
_fb9_1:
    li r30, 0x0
    b _fb9_loop_cond
_fb9_loop:
    clrlwi r0, r31, 24
    clrlwi r0, r0, 31
    cmpwi r0, 0x0
    beq _fb9_skip
    clrlwi r0, r30, 24
    mulli r0, r0, 0xc
    add r3, r28, r0
    lfs f0, 0x9b0(r3)
    stfs f0, 0x14(r1)
    lfs f0, 0x9b4(r3)
    stfs f0, 0x18(r1)
    lfs f0, 0x9b8(r3)
    stfs f0, 0x1c(r1)
    lfs f0, lbl_803E8F38(r0)
    stfs f0, 0x10(r1)
    li r3, 0x2
    li r4, 0x6
    bl fn_80022264
    clrlwi r25, r3, 24
    lis r26, 0x1
    b _fb9_in_cond
_fb9_in_body:
    li r3, 0x0
    li r4, 0x1
    bl fn_80022264
    mr r4, r3
    mr r3, r27
    addi r4, r4, 0x1f9
    addi r5, r1, 0x8
    addi r6, r26, 0x1
    li r7, -0x1
    li r8, 0x0
    lwz r9, lbl_803DD708(r0)
    lwz r9, 0x0(r9)
    lwz r12, 0x8(r9)
    mtctr r12
    bctrl
    subi r25, r25, 0x1
_fb9_in_cond:
    clrlwi r0, r25, 24
    cmplwi r0, 0x0
    bne _fb9_in_body
    lbz r0, 0xbc(r29)
    extsb r0, r0
    clrlwi r3, r0, 24
    li r4, 0x9
    bl fn_8006EEA0
    mr r4, r3
    mr r3, r27
    bl fn_8000BB38
    lfs f1, lbl_803E8EDC(r0)
    bl fn_80014ACC
_fb9_skip:
    clrlwi r0, r31, 24
    srawi r0, r0, 1
    clrlwi r31, r0, 24
    addi r30, r30, 0x1
_fb9_loop_cond:
    clrlwi r0, r31, 24
    cmplwi r0, 0x0
    bne _fb9_loop
    addi r11, r1, 0x40
    bl _restgpr_25
    lwz r0, 0x44(r1)
    mtlr r0
    addi r1, r1, 0x40
    blr
}

int fn_802BBAEC(void) {
    return 0xd0c;
}

int fn_802BBAF4(void) {
    return 0x43;
}

#pragma scheduling off
void fn_802BBAFC(void* obj) {
    fn_8003709C(obj, 10);
}
#pragma scheduling reset

asm void fn_802BBB20(void* a, void* b, void* c, void* d, void* e, signed char f) {
    nofralloc
    stwu r1, -0x30(r1)
    mflr r0
    stw r0, 0x34(r1)
    addi r11, r1, 0x30
    bl _savegpr_25
    mr r25, r3
    mr r26, r4
    mr r27, r5
    mr r28, r6
    mr r29, r7
    mr r30, r8
    lwz r31, 0xb8(r25)
    extsb r0, r30
    cmpwi r0, -0x1
    bne _fbb_0
    lfs f1, lbl_803E8EF0(r0)
    bl fn_8003B9EC
    mr r3, r25
    li r4, 0x1
    addi r5, r31, 0x9e8
    addi r6, r31, 0x9ec
    addi r7, r31, 0x9f0
    li r8, 0x0
    bl fn_80038524
    mr r3, r25
    li r4, 0x2
    li r5, 0x4
    addi r6, r31, 0x9b0
    bl fn_80038378
_fbb_0:
    lbz r0, 0xa8a(r31)
    cmplwi r0, 0x2
    beq _fbb_end
    extsb r0, r30
    cmpwi r0, 0x0
    beq _fbb_end
    mr r3, r25
    mr r4, r26
    mr r5, r27
    mr r6, r28
    mr r7, r29
    lfs f1, lbl_803E8EF0(r0)
    bl fn_8003B9EC
    mr r3, r25
    li r4, 0x1
    addi r5, r31, 0x9e8
    addi r6, r31, 0x9ec
    addi r7, r31, 0x9f0
    li r8, 0x0
    bl fn_80038524
    mr r3, r25
    li r4, 0x2
    li r5, 0x4
    addi r6, r31, 0x9b0
    bl fn_80038378
_fbb_end:
    addi r11, r1, 0x30
    bl _restgpr_25
    lwz r0, 0x34(r1)
    mtlr r0
    addi r1, r1, 0x30
    blr
}
