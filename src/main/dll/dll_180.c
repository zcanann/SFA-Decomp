#include "ghidra_import.h"
#include "main/dll/dll_180.h"

extern uint FUN_80017690();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80190148();
extern undefined4 FUN_801905c4();
extern undefined4 FUN_80190bd4();

extern undefined4 DAT_803ddb38;

/*
 * --INFO--
 *
 * Function: FUN_801916a0
 * EN v1.0 Address: 0x801916A0
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191A28
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801916a0(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (DAT_803ddb38 < 0) {
    if ((*(char *)(*(int *)(param_1 + 0x4c) + 0x1a) == -1) || ((*(byte *)(iVar2 + 0xe) & 0x20) != 0)
       ) {
      if ((*(byte *)(iVar2 + 0xe) & 0x40) == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
    }
    else {
      if ((*(char *)(iVar2 + 0xd) == '\0') && (*(char *)(iVar2 + 0xc) == '\0')) {
        uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x20);
        if ((uVar1 == 0xffffffff) || (uVar1 = FUN_80017690(uVar1), uVar1 != 0)) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xe7;
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 1;
        }
        else {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) & 0xfe;
      }
      if (*(int *)(param_1 + 0x74) != 0) {
        FUN_800400b0();
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xe7;
    *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 1;
    if (*(int *)(param_1 + 0x74) != 0) {
      FUN_800400b0();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801916e8
 * EN v1.0 Address: 0x801916E8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191BD4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801916e8(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0x4c) + 0x1a) != -1) {
    FUN_801905c4(param_1);
  }
  FUN_80190148(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80191730
 * EN v1.0 Address: 0x80191730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191C1C
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80191730(short *param_1,int param_2)
{
}
