#include "ghidra_import.h"
#include "main/dll/SC/SClightfoot.h"

extern undefined4 FUN_8003709c();
extern undefined4 FUN_80038524();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80115088();

extern undefined4 DAT_803dcc60;

/*
 * --INFO--
 *
 * Function: FUN_801d6484
 * EN v1.0 Address: 0x801D6484
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d6484(int param_1)
{
  if (DAT_803dcc60 == *(int *)(*(int *)(param_1 + 0x4c) + 0x14)) {
    DAT_803dcc60 = -1;
  }
  FUN_8003709c(param_1,0x4d);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d64c4
 * EN v1.0 Address: 0x801D64C4
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d64c4(short *param_1)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  FUN_8003b9ec((int)param_1);
  FUN_80115088(param_1,iVar2,0);
  iVar1 = 0;
  do {
    FUN_80038524(param_1,iVar1,(float *)(iVar2 + 0x8e0),(undefined4 *)(iVar2 + 0x8e4),
                 (float *)(iVar2 + 0x8e8),0);
    iVar2 = iVar2 + 0xc;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return;
}
