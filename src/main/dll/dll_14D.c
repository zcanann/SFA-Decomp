#include "ghidra_import.h"
#include "main/dll/dll_14D.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern undefined4 FUN_80036f50();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();

extern undefined4* DAT_803dd6d4;
extern f32 FLOAT_803e44e4;

/*
 * --INFO--
 *
 * Function: FUN_8017f1ec
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8017F1EC
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f1ec(undefined2 *param_1)
{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e44e4;
  iVar5 = *(int *)(param_1 + 0x26);
  pbVar4 = *(byte **)(param_1 + 0x5c);
  if (*(int *)(pbVar4 + 4) == 0) {
    uVar2 = FUN_80036f50((uint)*(byte *)(iVar5 + 0x1c),param_1,local_18);
    *(undefined4 *)(pbVar4 + 4) = uVar2;
    if (*(int *)(pbVar4 + 4) == 0) {
      return;
    }
    if ((int)*(short *)(iVar5 + 0x1a) == 0xffffffff) {
      pbVar4[2] = 0;
    }
    else {
      uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x1a));
      pbVar4[2] = (byte)uVar3;
    }
    *pbVar4 = 1;
  }
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0xc);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0x10);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*(int *)(pbVar4 + 4) + 0x14);
  *param_1 = **(undefined2 **)(pbVar4 + 4);
  param_1[2] = *(undefined2 *)(*(int *)(pbVar4 + 4) + 4);
  param_1[1] = *(undefined2 *)(*(int *)(pbVar4 + 4) + 2);
  bVar1 = *pbVar4;
  if (bVar1 == 2) {
    uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x18));
    if (uVar3 != 0) {
      *pbVar4 = 1;
    }
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    if ((pbVar4[2] == 0) || ((*(byte *)(iVar5 + 0x1f) & 1) != 0)) {
      if (((int)*(short *)(iVar5 + 0x18) == 0xffffffff) ||
         (uVar3 = FUN_80020078((int)*(short *)(iVar5 + 0x18)), uVar3 != 0)) {
        if ((*(byte *)((int)param_1 + 0xaf) & 1) == 0) {
          *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) | 0x20;
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
        }
        else {
          if ((*(byte *)(iVar5 + 0x1f) & 2) != 0) {
            FUN_800201ac((int)*(short *)(iVar5 + 0x18),0);
          }
          if ((int)*(short *)(iVar5 + 0x1a) != 0xffffffff) {
            FUN_800201ac((int)*(short *)(iVar5 + 0x1a),1);
          }
          if ((*(byte *)(iVar5 + 0x1f) & 4) == 0) {
            pbVar4[1] = pbVar4[1] + 1;
            if (*(byte *)(iVar5 + 0x1e) < pbVar4[1]) {
              pbVar4[1] = *(byte *)(iVar5 + 0x1d);
            }
          }
          else {
            uVar3 = FUN_80022264((uint)*(byte *)(iVar5 + 0x1d),(uint)*(byte *)(iVar5 + 0x1e));
            pbVar4[1] = (byte)uVar3;
          }
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
          pbVar4[2] = 1;
          (**(code **)(*DAT_803dd6d4 + 0x48))(pbVar4[1],param_1,0xffffffff);
        }
      }
      else {
        *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) & 0xdf;
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        *pbVar4 = 2;
      }
    }
    else {
      *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) = *(byte *)(*(int *)(pbVar4 + 4) + 0xaf) & 0xdf;
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
      *pbVar4 = 3;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f4d8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8017F4D8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f4d8(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017f508
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8017F508
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017f508(int param_1)
{
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_80041110();
  }
  return;
}
