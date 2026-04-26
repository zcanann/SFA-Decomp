#include "ghidra_import.h"
#include "main/dll/dll_227.h"

extern undefined4 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017548();
extern undefined4 FUN_80017584();
extern undefined4 FUN_800175cc();
extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80080f70();
extern undefined8 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern undefined4 dll_DIM_BossGutSpik_update();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;
extern undefined4 DAT_803de828;
extern undefined4 DAT_803de830;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de81c;
extern f32 FLOAT_803de820;
extern f32 FLOAT_803e5928;
extern f32 FLOAT_803e5950;
extern f32 FLOAT_803e5954;
extern f32 FLOAT_803e5958;
extern f32 FLOAT_803e595c;

/*
 * --INFO--
 *
 * Function: FUN_801be8f8
 * EN v1.0 Address: 0x801BE8F8
 * EN v1.0 Size: 1296b
 * EN v1.1 Address: 0x801BEA00
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801be8f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  byte bVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  undefined uStack_28;
  undefined local_27;
  undefined local_26;
  undefined local_25 [37];
  
  uVar3 = FUN_80286840();
  iVar9 = *(int *)(uVar3 + 0xb8);
  iVar8 = *(int *)(uVar3 + 0x4c);
  if (DAT_803de810 != 0) {
    FUN_80017584(DAT_803de810,local_25,&local_26,&local_27,&uStack_28);
    FUN_80017548(DAT_803de810,local_25[0],local_26,local_27,0xc0);
    if ((*(char *)(DAT_803de810 + 0x2f8) != '\0') && (*(char *)(DAT_803de810 + 0x4c) != '\0')) {
      sVar2 = (ushort)*(byte *)(DAT_803de810 + 0x2f9) + (short)*(char *)(DAT_803de810 + 0x2fa);
      if (sVar2 < 0) {
        sVar2 = 0;
        *(undefined *)(DAT_803de810 + 0x2fa) = 0;
      }
      else if (0xc < sVar2) {
        uVar4 = FUN_80017760(0xfffffff4,0xc);
        sVar2 = sVar2 + (short)uVar4;
        if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(DAT_803de810 + 0x2fa) = 0;
        }
      }
      *(char *)(DAT_803de810 + 0x2f9) = (char)sVar2;
    }
  }
  if (*(int *)(uVar3 + 0xf4) == 0) {
    for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar7 = iVar7 + 1) {
      bVar1 = *(byte *)(param_11 + iVar7 + 0x81);
      if (bVar1 == 3) {
        (**(code **)(*DAT_803dd72c + 0x50))(0x1c,1,0);
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          FUN_80080f80(7,1,0);
          param_2 = (double)FLOAT_803e595c;
          param_3 = (double)FLOAT_803e5950;
          FUN_80080f70(param_2,param_2,param_3,7);
          uVar5 = 0x7f;
          uVar6 = 0x28;
          uVar10 = FUN_80080f7c(7,0xff,0xb4,0xb4,0x7f,0x28);
          FUN_80006728(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3,uVar3,
                       0xd8,0,uVar5,uVar6,in_r9,in_r10);
          FUN_800067c0((int *)0xee,1);
        }
        else if (bVar1 != 0) {
          (**(code **)(*DAT_803dd72c + 0x50))(0x1c,1,1);
        }
      }
      else if (bVar1 == 5) {
        if (DAT_803de810 != 0) {
          FUN_800175cc((double)FLOAT_803e5950,DAT_803de810,'\0');
        }
      }
      else if ((bVar1 < 5) && (DAT_803de810 != 0)) {
        FUN_800175cc((double)FLOAT_803e5950,DAT_803de810,'\x01');
      }
    }
    if (FLOAT_803de81c <= FLOAT_803de820) {
      FUN_80006824(uVar3,0x189);
      FLOAT_803de81c = FLOAT_803de81c + FLOAT_803e5954;
      FUN_80006b94((double)FLOAT_803e5958);
    }
    FLOAT_803de820 = FLOAT_803de820 + FLOAT_803dc074;
    if (*(short *)(uVar3 + 0xb4) != -1) {
      iVar7 = (**(code **)(*DAT_803dd738 + 0x30))(uVar3,iVar9,1);
      if (iVar7 == 0) goto LAB_801bee08;
      uVar10 = extraout_f1;
      if (((int)*(short *)(iVar9 + 0x3f6) != 0xffffffff) &&
         (uVar4 = FUN_80017690((int)*(short *)(iVar9 + 0x3f6)), uVar4 != 0)) {
        uVar10 = (**(code **)(*DAT_803dd6d4 + 0x58))(param_11,(int)*(short *)(iVar8 + 0x2c));
        *(undefined2 *)(iVar9 + 0x3f6) = 0xffff;
      }
      bVar1 = *(byte *)(iVar9 + 0x405);
      if (bVar1 == 1) {
        iVar8 = (**(code **)(*DAT_803dd738 + 0x34))
                          (uVar3,param_11,iVar9,&DAT_803de830,&DAT_803de828,0);
        if (iVar8 != 0) {
          (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e5928,uVar3,iVar9,1);
        }
      }
      else if ((bVar1 == 0) || (2 < bVar1)) {
        *(undefined2 *)(param_11 + 0x6e) = 0xffff;
        *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
      }
      else {
        *(undefined2 *)(param_11 + 0x6e) = 0;
        dll_DIM_BossGutSpik_update(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    uVar3,param_11,iVar9,iVar9);
        if (*(char *)(iVar9 + 0x405) == '\x01') {
          *(undefined2 *)(iVar9 + 0x270) = 0;
          (**(code **)(*DAT_803dd70c + 8))
                    ((double)FLOAT_803e5950,(double)FLOAT_803e5950,uVar3,iVar9,&DAT_803de830,
                     &DAT_803de828);
          *(undefined *)(param_11 + 0x56) = 0;
        }
      }
    }
    if (*(short *)(uVar3 + 0xb4) == -1) {
      *(ushort *)(iVar9 + 0x400) = *(ushort *)(iVar9 + 0x400) | 2;
    }
  }
LAB_801bee08:
  FUN_8028688c();
  return;
}
