#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283134.h"
#include "main/unknown/autos/placeholder_80284988.h"

extern undefined4 DAT_803be6f6;
extern undefined4 DAT_803be71a;
extern undefined4 DAT_803be73e;
extern undefined4 DAT_803be762;
extern undefined4 DAT_803be786;
extern undefined4 DAT_803be7aa;
extern undefined4 DAT_803be7ce;
extern undefined4 DAT_803be7f2;
extern undefined4 DAT_803be816;
extern undefined4 DAT_803be83a;
extern undefined4 DAT_803be85e;
extern undefined4 DAT_803be882;
extern undefined4 DAT_803be8a6;
extern undefined4 DAT_803be8ca;
extern undefined4 DAT_803be8ee;
extern undefined4 DAT_803be912;
extern undefined4 DAT_803be936;
extern undefined4 DAT_803be95a;
extern undefined4 DAT_803be97e;
extern undefined4 DAT_803be9a2;
extern undefined4 DAT_803be9c6;
extern undefined4 DAT_803be9ea;
extern undefined4 DAT_803bea0e;
extern undefined4 DAT_803bea32;
extern undefined4 DAT_803bea56;
extern undefined4 DAT_803bea7a;
extern undefined4 DAT_803bea9e;
extern undefined4 DAT_803beac2;
extern undefined4 DAT_803beae6;
extern undefined4 DAT_803beb0a;
extern undefined4 DAT_803beb2e;
extern undefined4 DAT_803beb52;
extern undefined4 DAT_803beb76;
extern undefined4 DAT_803beb9a;
extern undefined4 DAT_803bebbe;
extern undefined4 DAT_803bebe2;
extern undefined4 DAT_803bec06;
extern undefined4 DAT_803bec2a;
extern undefined4 DAT_803bec4e;
extern undefined4 DAT_803bec72;
extern undefined4 DAT_803bec96;
extern undefined4 DAT_803becba;
extern undefined4 DAT_803becde;
extern undefined4 DAT_803bed02;
extern undefined4 DAT_803bed26;
extern undefined4 DAT_803bed4a;
extern undefined4 DAT_803bed6e;
extern undefined4 DAT_803bed92;
extern undefined4 DAT_803bedb6;
extern undefined4 DAT_803bedda;
extern undefined4 DAT_803bedfe;
extern undefined4 DAT_803bee22;
extern undefined4 DAT_803bee46;
extern undefined4 DAT_803bee6a;
extern undefined4 DAT_803bee8e;
extern undefined4 DAT_803beeb2;
extern undefined4 DAT_803beed6;
extern undefined4 DAT_803beefa;
extern undefined4 DAT_803bef1e;
extern undefined4 DAT_803bef42;
extern undefined4 DAT_803bef66;
extern undefined4 DAT_803bef8a;
extern undefined4 DAT_803befae;
extern undefined4 DAT_803befd2;
extern undefined4 DAT_803d4900;
extern u8 lbl_803DE238;
extern u8 lbl_803DE370;
extern u8 lbl_803DE37D;
extern u8 lbl_803DE37E;
extern u8 lbl_803DE37F;
extern u32 lbl_803DE348;
extern u8 *lbl_803DE344;

extern void hwSetSRCType(int slot, u32 value);
extern void hwSetPolyPhaseFilter(int slot, u32 value);
extern void hwSetITDMode(int slot, u32 value);
void hwSetTimeOffset(u8 value);
extern void fn_8027BDE0(void);
extern void fn_80284878(void);
extern void fn_80284998(void);
extern void fn_80284AF4(void);
extern void fn_80284A8C(void);
extern u32 fn_8028478C(void *callback, u32 flags, u32 value);
extern u32 fn_8027BA04(u32 valueA, u32 valueB, u32 enabled);
extern u32 fn_802848D8(u32 flags);
extern void fn_80284858(void);
extern void fn_802737E8(void);
extern void fn_802848AC(void);
extern void fn_802849CC(void);
extern void fn_8027F14C(void);
extern void fn_8026EC44(u32 value);
extern void fn_80271498(u32 value);
extern void fn_80280C30(void);
extern void fn_80272F70(void);
extern void fn_8027B25C(void);

/*
 * --INFO--
 *
 * Function: snd_handle_irq
 * EN v1.0 Address: 0x80282FE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283134
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void snd_handle_irq(void)
{
    u32 offset;
    u32 i;
    u8 *entry;

    if (lbl_803DE238 == 0) {
        return;
    }

    fn_802737E8();
    fn_80284B2C();
    fn_802848AC();
    fn_802849CC();
    fn_80284B4C();
    fn_80284B2C();
    fn_8027F14C();
    fn_80284B4C();
    fn_80284B2C();

    lbl_803DE37E = (lbl_803DE37E + 1) % 3;
    lbl_803DE37F ^= 1;

    offset = 0;
    i = 0;
    while ((u8)i < lbl_803DE37D) {
        entry = lbl_803DE344;
        *(u32 *)(entry + offset + 0x24) = 0;
        entry = lbl_803DE344;
        *(u32 *)(entry + offset + 0x28) = 0;
        entry = lbl_803DE344;
        *(u32 *)(entry + offset + 0x2c) = 0;
        entry = lbl_803DE344;
        *(u32 *)(entry + offset + 0x30) = 0;
        entry = lbl_803DE344;
        *(u32 *)(entry + offset + 0x34) = 0;
        offset += 0xf4;
        i++;
    }

    fn_80284B4C();

    i = 0;
    while ((u8)i < 5) {
        fn_80284B2C();
        hwSetTimeOffset(i);
        fn_8026EC44(0x100);
        fn_80271498(0x100);
        fn_80284B4C();
        i++;
    }

    fn_80284B2C();
    hwSetTimeOffset(0);
    fn_80280C30();
    fn_80284B4C();
    fn_80284B2C();
    fn_80272F70();
    fn_80284B4C();
    fn_80284B2C();
    fn_8027B25C();
    fn_80284B4C();
}

/*
 * --INFO--
 *
 * Function: hwInit
 * EN v1.0 Address: 0x80282FE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80283418
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int hwInit(u32 value, u8 valueA, u8 valueB, u32 flags)
{
    fn_80284A8C();
    lbl_803DE37F = 0;
    lbl_803DE37E = 0;
    lbl_803DE348 = 0;

    if (fn_8028478C(snd_handle_irq, flags, value) != 0 &&
        fn_8027BA04(valueA, valueB, (flags & 1) != 0) != 0 &&
        fn_802848D8(flags) != 0) {
        fn_80284ABC();
        fn_80284858();
        return 0;
    }

    return -1;
}

void hwExit(void)
{
    fn_80284AF4();
    fn_80284998();
    fn_8027BDE0();
    fn_80284878();
    fn_80284ABC();
    fn_80284AB8();
}

void hwSetTimeOffset(u8 value)
{
    lbl_803DE370 = value;
}

u8 hwGetTimeOffset(void)
{
    return lbl_803DE370;
}

#pragma peephole off
int hwIsActive(int slot)
{
    u8 *entry;
    int active;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    active = entry[0xec];
    return active != 0;
}
#pragma peephole reset

void hwSetMesgCallback(u32 value)
{
    lbl_803DE348 = value;
}

void hwSetPriority(int slot, u32 value)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    *(u32 *)(entry + 0x1c) = value;
}

void hwInitSamplePlayback(int slot, u16 value70, u32 *values, u32 resetAdsr, u32 priority, u32 value18, u32 resetSrc, u32 itdMode)
{
    u8 *entry;
    u32 offset;
    u32 inputOffset;
    u32 flags;
    u32 i;
    u32 zero;
    u32 valueA;
    u32 valueB;
    u32 *dst;

    zero = 0;
    inputOffset = 0;
    flags = 0;
    i = 0;
    offset = slot * 0xf4;

    while ((u8)i <= lbl_803DE370) {
        entry = lbl_803DE344;
        entry += inputOffset;
        entry += offset;
        flags |= *(u32 *)(entry + 0x24) & 0x20;
        *(u32 *)(entry + 0x24) = zero;
        inputOffset += 4;
        i++;
    }

    entry = lbl_803DE344;
    entry += offset;
    *(u32 *)(entry + 0x24) = flags;
    entry = lbl_803DE344;
    entry += offset;
    *(u32 *)(entry + 0x1c) = priority;
    entry = lbl_803DE344;
    entry += offset;
    *(u32 *)(entry + 0x18) = value18;
    entry = lbl_803DE344;
    entry += offset;
    *(u32 *)(entry + 0xf0) = zero;
    entry = lbl_803DE344;
    entry += offset;
    *(u16 *)(entry + 0x70) = value70;

    entry = lbl_803DE344;
    entry += offset;
    dst = (u32 *)(entry + 0x74);
    valueA = values[0];
    valueB = values[1];
    dst[0] = valueA;
    dst[1] = valueB;
    valueA = values[2];
    valueB = values[3];
    dst[2] = valueA;
    dst[3] = valueB;
    valueA = values[4];
    valueB = values[5];
    dst[4] = valueA;
    dst[5] = valueB;
    valueA = values[6];
    valueB = values[7];
    dst[6] = valueA;
    dst[7] = valueB;

    if (resetAdsr != 0) {
        entry = lbl_803DE344;
        entry += offset;
        *(u8 *)(entry + 0xa4) = zero;
        entry = lbl_803DE344;
        entry += offset;
        *(u32 *)(entry + 0xb8) = zero;
        entry = lbl_803DE344;
        entry += offset;
        *(u32 *)(entry + 0xbc) = zero;
        entry = lbl_803DE344;
        entry += offset;
        *(u16 *)(entry + 0xc0) = 0x7fff;
        entry = lbl_803DE344;
        entry += offset;
        *(u32 *)(entry + 0xc4) = zero;
    }

    entry = lbl_803DE344;
    entry += offset;
    *(u8 *)(entry + 0xe4) = 0xff;
    entry = lbl_803DE344;
    entry += offset;
    *(u8 *)(entry + 0xe5) = 0xff;
    entry = lbl_803DE344;
    entry += offset;
    *(u8 *)(entry + 0xe6) = 0xff;
    entry = lbl_803DE344;
    entry += offset;
    *(u8 *)(entry + 0xe7) = 0xff;

    if (resetSrc != 0) {
        hwSetSRCType(slot, 0);
        hwSetPolyPhaseFilter(slot, 1);
    }
    hwSetITDMode(slot, itdMode);
}
