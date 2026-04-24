#include "ghidra_import.h"
#include "main/dll/LGT/LGTdirectionallight.h"

extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017710();
extern int FUN_80017a98();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_802c2c08;
extern undefined4 DAT_802c2c0c;
extern undefined4 DAT_802c2c10;
extern undefined4 DAT_802c2c14;
extern undefined4 DAT_802c2c18;
extern undefined4 DAT_802c2c1c;
extern undefined4 DAT_802c2c20;
extern undefined4 DAT_802c2c24;
extern undefined4 DAT_802c2c28;
extern undefined4 DAT_802c2c2c;
extern undefined4 DAT_802c2c30;
extern undefined4 DAT_802c2c34;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e6ae0;
extern f64 DOUBLE_803e6ae8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e6aa0;
extern f32 FLOAT_803e6aa4;
extern f32 FLOAT_803e6aa8;
extern f32 FLOAT_803e6ab8;
extern f32 FLOAT_803e6abc;
extern f32 FLOAT_803e6ac0;
extern f32 FLOAT_803e6ac4;
extern f32 FLOAT_803e6ac8;
extern f32 FLOAT_803e6acc;
extern f32 FLOAT_803e6ad0;
extern f32 FLOAT_803e6ad4;
extern f32 FLOAT_803e6ad8;
extern f32 FLOAT_803e6af0;
extern f32 FLOAT_803e6af4;
extern f32 FLOAT_803e6af8;

/*
 * --INFO--
 *
 * Function: FUN_801f3c7c
 * EN v1.0 Address: 0x801F3C7C
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x801F3E04
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f3c7c(void)
{
  int iVar1;
  ushort uVar2;
  int iVar3;
  undefined2 *puVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar11;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined local_4c;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  undefined4 local_38;
  uint uStack_34;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  
  uVar11 = FUN_80286840();
  puVar4 = (undefined2 *)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  piVar8 = *(int **)(puVar4 + 0x5c);
  local_78 = DAT_802c2c08;
  local_74 = DAT_802c2c0c;
  local_70 = DAT_802c2c10;
  local_6c = DAT_802c2c14;
  local_68 = DAT_802c2c18;
  local_64 = DAT_802c2c1c;
  local_60 = DAT_802c2c20;
  local_5c = DAT_802c2c24;
  local_58 = DAT_802c2c28;
  local_54 = DAT_802c2c2c;
  local_50 = DAT_802c2c30;
  local_4c = DAT_802c2c34;
  *puVar4 = (short)(((int)*(char *)(iVar6 + 0x18) & 0x3fU) << 10);
  if (*(short *)(iVar6 + 0x1a) < 1) {
    *(float *)(puVar4 + 4) = FLOAT_803e6abc;
  }
  else {
    uStack_44 = (int)*(short *)(iVar6 + 0x1a) ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(puVar4 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e6ae0) / FLOAT_803e6ab8;
  }
  *(undefined *)(piVar8 + 5) = *(undefined *)(iVar6 + 0x19);
  piVar8[4] = (int)*(short *)(iVar6 + 0x1e);
  *(undefined *)((int)piVar8 + 0x15) = 1;
  if ((*(ushort *)(iVar6 + 0x1c) & 0x20) == 0) {
    *(undefined *)((int)piVar8 + 0x16) = 3;
  }
  else {
    *(undefined *)((int)piVar8 + 0x16) = 0;
  }
  if ((*(byte *)(iVar6 + 0x22) & 1) == 0) {
    *(undefined *)((int)piVar8 + 0x19) = 0;
  }
  else {
    *(undefined *)((int)piVar8 + 0x19) = 1;
  }
  if (*(char *)(piVar8 + 5) == '\0') {
    *(undefined *)((int)piVar8 + 0x17) = 1;
    uVar2 = *(ushort *)(iVar6 + 0x1c);
    if ((uVar2 & 4) == 0) {
      if ((uVar2 & 8) == 0) {
        if ((uVar2 & 0x10) == 0) {
          if ((uVar2 & 1) != 0) {
            *(undefined *)((int)piVar8 + 0x16) = 6;
          }
        }
        else {
          *(undefined *)((int)piVar8 + 0x15) = 6;
        }
      }
      else {
        *(undefined *)((int)piVar8 + 0x15) = 8;
      }
    }
    else {
      *(undefined *)((int)piVar8 + 0x15) = 4;
    }
  }
  if ((*(ushort *)(iVar6 + 0x1c) & 0x40) == 0) {
    *piVar8 = 0;
  }
  else {
    if (*piVar8 == 0) {
      piVar5 = FUN_80017624((int)puVar4,'\x01');
      *piVar8 = (int)piVar5;
      if (*piVar8 != 0) {
        FUN_800175b0(*piVar8,2);
      }
    }
    piVar5 = (int *)*piVar8;
    if (piVar5 != (int *)0x0) {
      if ((puVar4[0x23] == 0x705) || (puVar4[0x23] == 0x712)) {
        dVar9 = (double)FLOAT_803e6aa4;
        FUN_800175ec(dVar9,dVar9,dVar9,piVar5);
      }
      else {
        dVar9 = (double)FLOAT_803e6aa4;
        FUN_800175ec(dVar9,(double)FLOAT_803e6ac0,dVar9,piVar5);
      }
      iVar3 = (uint)*(byte *)((int)piVar8 + 0x15) * 3;
      FUN_8001759c(*piVar8,*(undefined *)((int)&local_78 + iVar3),
                   *(undefined *)((int)&local_78 + iVar3 + 1),
                   *(undefined *)((int)&local_78 + iVar3 + 2),0xff);
      iVar3 = (uint)*(byte *)((int)piVar8 + 0x15) * 3;
      FUN_80017588(*piVar8,*(undefined *)((int)&local_78 + iVar3),
                   *(undefined *)((int)&local_78 + iVar3 + 1),
                   *(undefined *)((int)&local_78 + iVar3 + 2),0xff);
      FUN_800175d0((double)FLOAT_803e6ac4,(double)FLOAT_803e6ac8,*piVar8);
      FUN_800175cc((double)FLOAT_803e6aa4,*piVar8,'\x01');
      FUN_8001753c(*piVar8,1,3);
      iVar7 = (uint)*(byte *)((int)piVar8 + 0x15) * 3;
      dVar10 = (double)FLOAT_803e6acc;
      uStack_44 = (uint)*(byte *)((int)&local_78 + iVar7);
      local_48 = 0x43300000;
      iVar3 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,
                                                              (uint)*(byte *)((int)&local_78 + iVar7
                                                                             )) - DOUBLE_803e6ae8));
      local_40 = (longlong)iVar3;
      uStack_34 = (uint)*(byte *)((int)&local_78 + iVar7 + 1);
      local_38 = 0x43300000;
      iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_34) -
                                            DOUBLE_803e6ae8));
      local_30 = (longlong)iVar1;
      uStack_24 = (uint)*(byte *)((int)&local_78 + iVar7 + 2);
      local_28 = 0x43300000;
      iVar7 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_24) -
                                            DOUBLE_803e6ae8));
      local_20 = (longlong)iVar7;
      FUN_80017594(*piVar8,(char)iVar3,(char)iVar1,(char)iVar7,0xff);
      FUN_800175bc(*piVar8,1);
      if ((*(ushort *)(iVar6 + 0x1c) & 0x80) != 0) {
        if ((puVar4[0x23] == 0x705) || (puVar4[0x23] == 0x712)) {
          iVar3 = (uint)*(byte *)((int)piVar8 + 0x15) * 3;
          FUN_8001754c((double)(float)((double)FLOAT_803e6ad0 *
                                      (double)(FLOAT_803e6ad4 * *(float *)(puVar4 + 4))),
                       (double)FLOAT_803e6ad0,dVar9,in_f4,in_f5,in_f6,in_f7,in_f8,*piVar8,0,
                       (uint)*(byte *)((int)&local_78 + iVar3),
                       (uint)*(byte *)((int)&local_78 + iVar3 + 1),
                       (uint)*(byte *)((int)&local_78 + iVar3 + 2),0x8c,in_r9,in_r10);
        }
        else {
          iVar3 = (uint)*(byte *)((int)piVar8 + 0x15) * 3;
          FUN_8001754c((double)(FLOAT_803e6ad4 * *(float *)(puVar4 + 4)),dVar10,dVar9,in_f4,in_f5,
                       in_f6,in_f7,in_f8,*piVar8,0,(uint)*(byte *)((int)&local_78 + iVar3),
                       (uint)*(byte *)((int)&local_78 + iVar3 + 1),
                       (uint)*(byte *)((int)&local_78 + iVar3 + 2),0x8c,in_r9,in_r10);
        }
        FUN_80017544((double)FLOAT_803e6ad8,*piVar8);
      }
    }
  }
  if ((*(ushort *)(iVar6 + 0x1c) & 2) != 0) {
    *(undefined *)((int)piVar8 + 0x15) = 0;
  }
  puVar4[0x58] = puVar4[0x58] | 0x2000;
  piVar8[1] = (int)FLOAT_803e6aa8;
  piVar8[2] = (int)FLOAT_803e6aa0;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4138
 * EN v1.0 Address: 0x801F4138
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801F4274
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4138(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f416c
 * EN v1.0 Address: 0x801F416C
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x801F42B4
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f416c(short *param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short sVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  iVar4 = FUN_80017a98();
  if (iVar4 != 0) {
    dVar7 = (double)FUN_80017710((float *)(iVar4 + 0x18),(float *)(*(int *)(param_1 + 0x26) + 8));
    if (dVar7 <= (double)FLOAT_803e6af0) {
      fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 6);
      fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 8);
      fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 10);
      if ((FLOAT_803e6af4 < fVar1) || (fVar1 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 6) = FLOAT_803e6af8 * fVar1 * FLOAT_803dc074 + *(float *)(param_1 + 6);
      }
      if ((FLOAT_803e6af4 < fVar2) || (fVar2 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 8) = FLOAT_803e6af8 * fVar2 * FLOAT_803dc074 + *(float *)(param_1 + 8);
      }
      if ((FLOAT_803e6af4 < fVar3) || (fVar3 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 10) =
             FLOAT_803e6af8 * fVar3 * FLOAT_803dc074 + *(float *)(param_1 + 10);
      }
      sVar6 = *(short *)(iVar5 + 8);
      if ((-1 < sVar6) || ((-1 >= sVar6 && (*(int *)(param_1 + 0x7a) < 1)))) {
        if (sVar6 == 0) {
          *(undefined2 *)(iVar5 + 0xc) = 1;
        }
        *param_1 = *param_1 + 300;
        if (*(short *)(iVar5 + 8) < 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
        }
        else {
          for (sVar6 = 0; sVar6 < *(short *)(iVar5 + 8); sVar6 = sVar6 + 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
          }
        }
        *(int *)(param_1 + 0x7a) = -(int)*(short *)(iVar5 + 8);
      }
      else if ((sVar6 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
        *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
      }
    }
    else {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar5 + 0x14);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar5 + 0x18);
    }
  }
  return;
}
