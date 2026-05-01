#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283E4C.h"

extern undefined4 DAT_803dd280;
extern undefined4 DAT_803dd288;
extern undefined4 DAT_803defc4;
extern undefined4 DAT_803deff0;
extern u32 lbl_803DE334;
extern u8 *lbl_803DE344;
extern u32 lbl_803DE374;
extern u32 lbl_803DE378;

/*
 * --INFO--
 *
 * Function: hwSaveSample
 * EN v1.0 Address: 0x80283DFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283E4C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwSaveSample(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80283e00
 * EN v1.0 Address: 0x80283E00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283E74
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80283e00(int param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: hwRemoveSample
 * EN v1.0 Address: 0x80283E04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283EEC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwRemoveSample(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: hwSyncSampleMem
 * EN v1.0 Address: 0x80283E08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283F18
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwSyncSampleMem(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80283e0c
 * EN v1.0 Address: 0x80283E0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283F44
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80283e0c(int param_1,char param_2)
{
}

/* Pattern wrappers. */
void hwFrameDone(void) {}

void sndSetHooks(u32 *values)
{
  u32 first;
  u32 second;

  first = values[0];
  second = values[1];
  lbl_803DE374 = first;
  lbl_803DE378 = second;
}

void hwDisableHRTF(void)
{
  lbl_803DE334 = 0;
}

int hwGetVirtualSampleID(int slot)
{
  u8 *entry;

  slot *= 0xf4;
  entry = lbl_803DE344;
  entry += slot;
  if (entry[0xec] == 0) {
    return -1;
  }
  return *(int *)(entry + 0xe8);
}

int hwVoiceInStartup(int slot)
{
  u8 *entry;

  slot *= 0xf4;
  entry = lbl_803DE344;
  entry += slot;
  return entry[0xec] == 1;
}
