#include <PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/math.h>

extern float __fabsf(float);

static void __sinit_trigf_c(void);

/* lbl_802C2B20 source data lives in .rodata at lbl_802C2B20 */
extern const float lbl_802C2B20[4];

/* lbl_80332C4C and lbl_80332C2C arrays in .data */
extern const float lbl_80332C2C[];  /* lbl_80332C2C */
extern const float lbl_80332C4C[];  /* lbl_80332C4C */

/* lbl_80332A18 mutable scratch array (initialized by __sinit_trigf_c) */
extern float lbl_80332A18[4];

extern const float lbl_803E7E38;  /* was lbl_803E7E38 */
extern const float lbl_803E7E3C;  /* was lbl_803E7E3C */
extern const float lbl_803E7E40;  /* was lbl_803E7E40 */
extern const double lbl_803E7E48; /* was lbl_803E7E48 */

float sinf(float x);
float cosf(float x);
__declspec(weak) float cos__Ff(float x);
__declspec(weak) float sin__Ff(float x);

#pragma dont_inline on

asm float tanf(float x)
{
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x20(r1)
    stfd f31, 0x18(r1)
    stfd f30, 0x10(r1)
    fmr f30, f1
    bl cos__Ff
    fmr f31, f1
    fmr f1, f30
    bl sin__Ff
    fdivs f1, f1, f31
    lwz r0, 0x24(r1)
    lfd f31, 0x18(r1)
    lfd f30, 0x10(r1)
    mtlr r0
    addi r1, r1, 0x20
    blr
}

__declspec(weak) float cos__Ff(float x) { return cosf(x); }

__declspec(weak) float sin__Ff(float x) { return sinf(x); }

asm float cosf(float x)
{
    nofralloc
    mflr r0
    lis r3, lbl_80332A18@ha
    stw r0, 0x4(r1)
    addi r3, r3, lbl_80332A18@l
    stwu r1, -0x28(r1)
    stfd f31, 0x20(r1)
    stw r31, 0x1c(r1)
    stfs f1, 0x8(r1)
    lfs f0, lbl_803E7E38(r0)
    lwz r0, 0x8(r1)
    lfs f6, 0x8(r1)
    clrrwi. r0, r0, 31
    fmuls f1, f0, f6
    beq _cos_0
    lfs f0, lbl_803E7E3C(r0)
    fsubs f0, f1, f0
    fctiwz f0, f0
    stfd f0, 0x10(r1)
    lwz r4, 0x14(r1)
    b _cos_1
_cos_0:
    lfs f0, lbl_803E7E3C(r0)
    fadds f0, f0, f1
    fctiwz f0, f0
    stfd f0, 0x10(r1)
    lwz r4, 0x14(r1)
_cos_1:
    slwi r0, r4, 1
    lfd f1, lbl_803E7E48(r0)
    xoris r0, r0, 0x8000
    lfs f2, 0x0(r3)
    stw r0, 0x14(r1)
    lis r0, 0x4330
    lfs f3, 0x4(r3)
    clrlwi r31, r4, 30
    stw r0, 0x10(r1)
    lfs f4, 0x8(r3)
    lfd f0, 0x10(r1)
    lfs f5, 0xc(r3)
    fsubs f0, f0, f1
    fsubs f0, f6, f0
    fmadds f0, f2, f6, f0
    fmadds f0, f3, f6, f0
    fmadds f0, f4, f6, f0
    fmadds f31, f5, f6, f0
    fmr f1, f31
    bl __fabsf
    lfs f0, lbl_803E7E40(r0)
    fcmpo cr0, f1, f0
    bge _cos_2
    lis r3, lbl_80332C2C@ha
    slwi r4, r31, 3
    addi r0, r3, lbl_80332C2C@l
    add r3, r0, r4
    lfs f1, 0x0(r3)
    lfs f0, 0x4(r3)
    fnmsubs f1, f31, f1, f0
    b _cos_5
_cos_2:
    clrlwi. r0, r31, 31
    fmuls f4, f31, f31
    beq _cos_4
    lis r3, lbl_80332C4C@ha
    addi r4, r3, lbl_80332C4C@l
    lfs f2, 0x4(r4)
    lis r3, lbl_80332C2C@ha
    lfs f1, 0xc(r4)
    addi r0, r3, lbl_80332C2C@l
    lfs f0, 0x14(r4)
    fmadds f3, f2, f4, f1
    lfs f2, 0x1c(r4)
    lfs f1, 0x24(r4)
    slwi r4, r31, 3
    add r3, r0, r4
    fmadds f3, f4, f3, f0
    lfs f0, 0x0(r3)
    fmadds f2, f4, f3, f2
    fnmadds f1, f4, f2, f1
    fmuls f1, f31, f1
    fmuls f1, f1, f0
    b _cos_5
_cos_4:
    lis r3, lbl_80332C4C@ha
    addi r4, r3, lbl_80332C4C@l
    lfs f2, 0x0(r4)
    lis r3, lbl_80332C2C@ha
    lfs f1, 0x8(r4)
    addi r3, r3, lbl_80332C2C@l
    slwi r0, r31, 3
    fmadds f3, f2, f4, f1
    lfs f0, 0x10(r4)
    lfs f2, 0x18(r4)
    add r3, r3, r0
    lfs f1, 0x20(r4)
    fmadds f3, f4, f3, f0
    lfs f0, 0x4(r3)
    fmadds f2, f4, f3, f2
    fmadds f1, f4, f2, f1
    fmuls f1, f1, f0
_cos_5:
    lwz r0, 0x2c(r1)
    lfd f31, 0x20(r1)
    lwz r31, 0x1c(r1)
    mtlr r0
    addi r1, r1, 0x28
    blr
}

asm float sinf(float x)
{
    nofralloc
    mflr r0
    lis r3, lbl_80332A18@ha
    stw r0, 0x4(r1)
    addi r3, r3, lbl_80332A18@l
    stwu r1, -0x28(r1)
    stfd f31, 0x20(r1)
    stw r31, 0x1c(r1)
    stfs f1, 0x8(r1)
    lfs f0, lbl_803E7E38(r0)
    lwz r0, 0x8(r1)
    lfs f6, 0x8(r1)
    clrrwi. r0, r0, 31
    fmuls f1, f0, f6
    beq _sin_0
    lfs f0, lbl_803E7E3C(r0)
    fsubs f0, f1, f0
    fctiwz f0, f0
    stfd f0, 0x10(r1)
    lwz r4, 0x14(r1)
    b _sin_1
_sin_0:
    lfs f0, lbl_803E7E3C(r0)
    fadds f0, f0, f1
    fctiwz f0, f0
    stfd f0, 0x10(r1)
    lwz r4, 0x14(r1)
_sin_1:
    slwi r0, r4, 1
    lfd f1, lbl_803E7E48(r0)
    xoris r0, r0, 0x8000
    lfs f2, 0x0(r3)
    stw r0, 0x14(r1)
    lis r0, 0x4330
    lfs f3, 0x4(r3)
    clrlwi r31, r4, 30
    stw r0, 0x10(r1)
    lfs f4, 0x8(r3)
    lfd f0, 0x10(r1)
    lfs f5, 0xc(r3)
    fsubs f0, f0, f1
    fsubs f0, f6, f0
    fmadds f0, f2, f6, f0
    fmadds f0, f3, f6, f0
    fmadds f0, f4, f6, f0
    fmadds f31, f5, f6, f0
    fmr f1, f31
    bl __fabsf
    lfs f0, lbl_803E7E40(r0)
    fcmpo cr0, f1, f0
    bge _sin_2
    lis r3, lbl_80332C2C@ha
    slwi r4, r31, 3
    addi r0, r3, lbl_80332C2C@l
    add r3, r0, r4
    lfs f1, 0x4(r3)
    lis r4, lbl_80332C4C@ha
    addi r4, r4, lbl_80332C4C@l
    lfs f0, 0x0(r3)
    fmuls f1, f31, f1
    lfs f2, 0x24(r4)
    fmadds f1, f2, f1, f0
    b _sin_5
_sin_2:
    clrlwi. r0, r31, 31
    fmuls f4, f31, f31
    beq _sin_4
    lis r3, lbl_80332C4C@ha
    addi r4, r3, lbl_80332C4C@l
    lfs f2, 0x0(r4)
    lis r3, lbl_80332C2C@ha
    lfs f1, 0x8(r4)
    addi r0, r3, lbl_80332C2C@l
    lfs f0, 0x10(r4)
    fmadds f3, f2, f4, f1
    lfs f2, 0x18(r4)
    lfs f1, 0x20(r4)
    slwi r4, r31, 3
    add r3, r0, r4
    fmadds f3, f4, f3, f0
    lfs f0, 0x0(r3)
    fmadds f2, f4, f3, f2
    fmadds f1, f4, f2, f1
    fmuls f1, f1, f0
    b _sin_5
_sin_4:
    lis r3, lbl_80332C4C@ha
    addi r4, r3, lbl_80332C4C@l
    lfs f2, 0x4(r4)
    lis r3, lbl_80332C2C@ha
    lfs f1, 0xc(r4)
    addi r3, r3, lbl_80332C2C@l
    slwi r0, r31, 3
    fmadds f3, f2, f4, f1
    lfs f0, 0x14(r4)
    lfs f2, 0x1c(r4)
    add r3, r3, r0
    lfs f1, 0x24(r4)
    fmadds f3, f4, f3, f0
    lfs f0, 0x4(r3)
    fmadds f2, f4, f3, f2
    fmadds f1, f4, f2, f1
    fmuls f1, f31, f1
    fmuls f1, f1, f0
_sin_5:
    lwz r0, 0x2c(r1)
    lfd f31, 0x20(r1)
    lwz r31, 0x1c(r1)
    mtlr r0
    addi r1, r1, 0x28
    blr
}

#pragma dont_inline reset

asm static void __sinit_trigf_c(void) {
    nofralloc
    lis r3, lbl_802C2B20@ha
    addi r4, r3, lbl_802C2B20@l
    lfs f0, 0x0(r4)
    lis r3, lbl_80332A18@ha
    stfsu f0, lbl_80332A18@l(r3)
    lfs f0, 0x4(r4)
    stfs f0, 0x4(r3)
    lfs f0, 0x8(r4)
    stfs f0, 0x8(r3)
    lfs f0, 0xc(r4)
    stfs f0, 0xc(r3)
    blr
}

__declspec(section ".ctors")
static void* const __sinit_trigf_c_ref = (void*)__sinit_trigf_c;

