#include "ghidra_import.h"
#include "main/dll/scene1C7.h"

extern undefined4 FUN_8001dc30();
extern undefined4 FUN_800201ac();
extern int FUN_8002bac4();
extern undefined4 FUN_80043604();
extern undefined4 FUN_80043658();
extern undefined4 FUN_8004832c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80296c78();

extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803e5d70;

/*
 * --INFO--
 *
 * Function: FUN_801c9470
 * EN v1.0 Address: 0x801C9470
 * EN v1.0 Size: 388b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9470(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  
  iVar2 = FUN_8028683c();
  piVar6 = *(int **)(iVar2 + 0xb8);
  iVar3 = FUN_8002bac4();
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 7) {
        FUN_80296c78(iVar3,2,1);
        FUN_800201ac(0x15f,1);
        FUN_800201ac(0xc6e,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0xb,3);
        FUN_80043604(0,0,1);
        uVar4 = FUN_8004832c(10);
        FUN_80043658(uVar4,0);
      }
      else if (bVar1 < 7) {
        if (bVar1 == 3) {
          *(byte *)((int)piVar6 + 0x15) = *(byte *)((int)piVar6 + 0x15) & 0x7f | 0x80;
        }
      }
      else if (bVar1 == 0xf) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
        if (*piVar6 != 0) {
          FUN_8001dc30((double)FLOAT_803e5d70,*piVar6,'\0');
        }
      }
      else if ((bVar1 < 0xf) && (0xd < bVar1)) {
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        if (*piVar6 != 0) {
          FUN_8001dc30((double)FLOAT_803e5d70,*piVar6,'\0');
        }
      }
    }
    *(undefined *)(param_3 + iVar5 + 0x81) = 0;
  }
  FUN_80286888();
  return;
}
