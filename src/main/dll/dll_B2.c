#include "ghidra_import.h"
#include "main/dll/dll_B2.h"

extern undefined4 FUN_8000e054();
extern undefined4 FUN_8003b9ec();
extern int FUN_80286838();
extern undefined4 FUN_80286884();

extern undefined4 DAT_803dc5f0;
extern undefined4 DAT_803de134;
extern undefined4 gCamcontrolTargetState;
extern undefined4 gCamcontrolState;
extern f32 FLOAT_803e22a8;

/*
 * --INFO--
 *
 * Function: FUN_80100d40
 * EN v1.0 Address: 0x80100D40
 * EN v1.0 Size: 492b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80100d40(void)
{
  int iVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  undefined uVar6;
  undefined4 *puVar7;
  undefined unaff_r30;
  undefined unaff_r31;
  
  iVar5 = FUN_80286838();
  uVar6 = gCamcontrolTargetState;
  iVar1 = DAT_803de134;
  iVar2 = *(int *)(gCamcontrolState + 0x120);
  if (iVar2 != 0) {
    gCamcontrolTargetState = 3;
    unaff_r30 = *(undefined *)(DAT_803de134 + 0x36);
    *(undefined *)(DAT_803de134 + 0x36) = 0xff;
    iVar5 = iVar2;
    unaff_r31 = uVar6;
  }
  if (iVar5 == 0) {
    *(undefined4 *)(iVar1 + 0x30) = 0;
  }
  else {
    if (*(int *)(iVar5 + 0x74) == 0) goto LAB_80100f14;
    puVar7 = (undefined4 *)(*(int *)(iVar5 + 0x74) + (uint)*(byte *)(iVar5 + 0xe4) * 0x18);
    bVar4 = *(byte *)(*(int *)(iVar5 + 0x78) + (uint)*(byte *)(iVar5 + 0xe4) * 5 + 4) & 0xf;
    if (bVar4 == 4) {
LAB_80100df8:
      uVar6 = 2;
    }
    else {
      if (bVar4 < 4) {
        if (bVar4 == 1) {
          uVar6 = 0;
          goto LAB_80100e04;
        }
      }
      else if (bVar4 == 9) goto LAB_80100df8;
      uVar6 = 1;
    }
LAB_80100e04:
    uVar3 = (uint)*(byte *)(iVar5 + 0xe8);
    if (3 < uVar3) {
      uVar3 = 0;
    }
    DAT_803dc5f0 = *(undefined2 *)(*(int *)(iVar5 + 0x50) + uVar3 * 2 + 0x7c);
    *(undefined4 *)(iVar1 + 0x18) = *puVar7;
    *(undefined4 *)(iVar1 + 0x1c) = puVar7[1];
    *(undefined4 *)(iVar1 + 0x20) = puVar7[2];
    *(undefined *)(iVar1 + 0xad) = uVar6;
    *(undefined4 *)(iVar1 + 0x30) = *(undefined4 *)(iVar5 + 0x30);
    if (*(int *)(iVar1 + 0x30) == 0) {
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar1 + 0x18);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar1 + 0x1c);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar1 + 0x20);
    }
    else {
      FUN_8000e054((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                   (double)*(float *)(iVar1 + 0x20),(float *)(iVar1 + 0xc),(float *)(iVar1 + 0x10),
                   (float *)(iVar1 + 0x14),*(int *)(iVar1 + 0x30));
    }
    *(undefined2 *)(iVar1 + 2) = 0;
    *(undefined2 *)(iVar1 + 4) = 0;
    *(float *)(iVar1 + 8) = FLOAT_803e22a8;
    *(undefined *)(iVar1 + 0x37) = *(undefined *)(iVar1 + 0x36);
    FUN_8003b9ec(iVar1);
  }
  iVar5 = *(int *)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
  *(ushort *)(iVar5 + 0x18) = *(ushort *)(iVar5 + 0x18) & 0xfff7;
  if (*(int *)(gCamcontrolState + 0x120) != 0) {
    gCamcontrolTargetState = unaff_r31;
    *(undefined *)(iVar1 + 0x36) = unaff_r30;
  }
LAB_80100f14:
  FUN_80286884();
  return;
}
