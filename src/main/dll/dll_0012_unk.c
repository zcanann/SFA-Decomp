/*
 * dll_0012_unk (DLL 0x12) - a tiny stub object DLL whose only live code is
 * a set of standalone object-DLL callbacks.
 *
 * Aside from dll_12_func09 (which latches a status word to 3) and
 * dll_12_func06_ret_0 (a constant 0 return), every entry is an empty
 * no-op/dummy callback. The bulk of the curve/sector code that Ghidra
 * attributed to this address range actually belongs to the dll_0014 sibling
 * TU; only these ten symbols (0x800D9EB4..0x800D9EE8) live here.
 */
#include "dolphin/types.h"
#include "main/dll/dll_0012_unk.h"

unsigned int lbl_803DD458;

void dll_12_func0A_nop(void)
{
}

void dll_12_func09(void)
{
    lbl_803DD458 = 0x3;
}

void dll_12_func08_nop(void)
{
}

void dll_12_func07_nop(void)
{
}

int dll_12_func06_ret_0(void)
{
    return 0x0;
}

void dll_12_func04_nop(void)
{
}

void dll_12_func03_nop(void)
{
}

void dll_12_func05_nop(void)
{
}

void Dummy12_release(void)
{
}

void Dummy12_initialise(void)
{
}

u32 lbl_803114D8[16] = {
    0, 0, 0, 0x000A0000,
    (u32)Dummy12_initialise, (u32)Dummy12_release, 0, (u32)dll_12_func03_nop,
    (u32)dll_12_func04_nop, (u32)dll_12_func05_nop, (u32)dll_12_func06_ret_0, (u32)dll_12_func07_nop,
    (u32)dll_12_func08_nop, (u32)dll_12_func09, (u32)dll_12_func0A_nop, 0,
};
