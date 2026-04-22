#include "ghidra_import.h"
#include "main/dll/fire.h"

extern uint FUN_80020078();
extern undefined4 FUN_80026ec4();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_8032a7b8;
extern undefined4 DAT_8032a7bc;
extern undefined4 DAT_8032a7c0;
extern f32 FLOAT_803e7144;
extern f32 FLOAT_803e7164;
extern f32 FLOAT_803e7168;
extern f32 FLOAT_803e716c;

/*
 * --INFO--
 *
 * Function: FUN_802093b4
 * EN v1.0 Address: 0x802093B4
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802093b4(void)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined8 uVar11;
  float local_58;
  float local_54;
  float local_50;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  iVar8 = *(int *)(iVar3 + 0xb8);
  iVar7 = **(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x4000;
  if (*(short *)(iVar3 + 0x46) == 0x4e0) {
    DAT_8032a7b8 = (int)*(float *)(iVar3 + 0xc);
    local_48 = (longlong)DAT_8032a7b8;
    DAT_8032a7bc = (int)*(float *)(iVar3 + 0x10);
    local_40 = (longlong)DAT_8032a7bc;
    DAT_8032a7c0 = (int)*(float *)(iVar3 + 0x14);
    local_38 = (longlong)DAT_8032a7c0;
  }
  else {
    dVar10 = (double)FLOAT_803e7164;
    for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar9 = iVar9 + 1) {
      FUN_80026ec4(iVar7,iVar9,&local_58);
      if ((double)local_54 < dVar10) {
        dVar10 = (double)local_54;
      }
    }
    for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar9 = iVar9 + 1) {
      FUN_80026ec4(iVar7,iVar9,&local_58);
      if ((double)local_54 == dVar10) {
        bVar2 = false;
        cVar1 = *(char *)(iVar8 + 0x68);
        for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
          iVar4 = iVar8 + iVar6 * 0xc;
          if ((local_58 == *(float *)(iVar4 + 4)) && (local_50 == *(float *)(iVar4 + 0xc))) {
            bVar2 = true;
            iVar6 = (int)cVar1;
          }
        }
        if (!bVar2) {
          *(float *)(iVar8 + cVar1 * 0xc + 4) = local_58;
          *(float *)(iVar8 + *(char *)(iVar8 + 0x68) * 0xc + 8) = local_54;
          *(float *)(iVar8 + *(char *)(iVar8 + 0x68) * 0xc + 0xc) = local_50;
          *(char *)(iVar8 + 0x68) = *(char *)(iVar8 + 0x68) + '\x01';
        }
      }
    }
    *(undefined *)(iVar8 + 0x69) = 0;
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - FLOAT_803e7144;
    *(undefined2 *)(iVar8 + 0x66) = *(undefined2 *)((int)uVar11 + 0x1e);
    *(undefined2 *)(iVar8 + 100) = *(undefined2 *)((int)uVar11 + 0x20);
    uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x66));
    *(char *)(iVar8 + 0x6b) = (char)uVar5;
    uVar5 = FUN_80020078((int)*(short *)(iVar8 + 100));
    *(char *)(iVar8 + 0x6a) = (char)uVar5;
    if (*(char *)(iVar8 + 0x6b) != '\0') {
      *(float *)(iVar3 + 0xc) = *(float *)(iVar3 + 0xc) + FLOAT_803e7168;
      *(float *)(iVar3 + 0x14) = *(float *)(iVar3 + 0x14) + FLOAT_803e716c;
      *(undefined *)(iVar8 + 0x69) = 4;
    }
  }
  FUN_8028688c();
  return;
}
