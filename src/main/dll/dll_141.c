#include "ghidra_import.h"
#include "main/dll/dll_141.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017760();
extern int FUN_80017a54();
extern undefined4 FUN_80017a70();
extern undefined4 FUN_80017a74();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_DisableObject();
extern void* ObjGroup_GetObjects();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8017504c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294bd4();
extern uint FUN_80294bd8();
extern uint FUN_80294c78();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_80321908;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803e4140;
extern undefined4 DAT_803e4144;
extern f64 DOUBLE_803e4198;
extern f64 DOUBLE_803e41b0;
extern f64 DOUBLE_803e41b8;
extern f64 DOUBLE_803e41c8;
extern f64 DOUBLE_803e41d0;
extern f32 lbl_803DC074;
extern f32 lbl_803E4148;
extern f32 lbl_803E414C;
extern f32 lbl_803E4150;
extern f32 lbl_803E4154;
extern f32 lbl_803E4158;
extern f32 lbl_803E415C;
extern f32 lbl_803E4160;
extern f32 lbl_803E4164;
extern f32 lbl_803E4168;
extern f32 lbl_803E416C;
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4190;
extern f32 lbl_803E4194;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41C4;

/*
 * --INFO--
 *
 * Function: magicdust_update
 * EN v1.0 Address: 0x801732A4
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x80173750
 * EN v1.1 Size: 2120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void magicdust_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  short sVar2;
  byte bVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 in_r7;
  char *in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  double dVar9;
  double dVar10;
  char local_28;
  char local_27 [3];
  uint local_24 [9];
  
  psVar4 = (short *)FUN_80286840();
  iVar5 = FUN_80017a98();
  iVar8 = *(int *)(psVar4 + 0x5c);
  while (iVar6 = ObjMsg_Pop((int)psVar4,local_24,(uint *)0x0,(uint *)0x0), iVar6 != 0) {
    if (local_24[0] == 0x7000b) {
      iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
      (*(code *)(*DAT_803dd6f8 + 0x18))(psVar4);
      FUN_80081118((double)lbl_803E4148,psVar4,(uint)*(byte *)(iVar8 + 0x27c),0x28);
      ObjHits_DisableObject((int)psVar4);
      FUN_80006824((uint)psVar4,*(ushort *)(iVar8 + 0x274));
      FUN_80006810((int)psVar4,0x56);
      FUN_80294d40(iVar5,(int)*(char *)(iVar6 + 0xb));
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
      *(float *)(iVar8 + 0x26c) = lbl_803E414C;
      FUN_800723a0();
      *(undefined *)(psVar4 + 0x1b) = 1;
    }
  }
  if ((*(byte *)(iVar8 + 0x27a) & 0x10) == 0) {
    if (((*(byte *)(iVar8 + 0x27a) & 0x40) == 0) &&
       (dVar9 = FUN_80017708((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18)),
       dVar9 < (double)lbl_803E4150)) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x10;
      local_28 = '\0';
      (*(code *)(*DAT_803dd708 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = '\x01';
      (*(code *)(*DAT_803dd708 + 8))
                (psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002,0xffffffff,&local_28);
      local_28 = '\x02';
      in_r7 = 0xffffffff;
      in_r8 = &local_28;
      in_r9 = *DAT_803dd708;
      (*(code *)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x272),0,0x10002);
    }
  }
  else {
    dVar9 = FUN_80017708((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18));
    if ((double)lbl_803E4150 <= dVar9) {
      *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xef;
      (*(code *)(*DAT_803dd6f8 + 0x18))(psVar4);
    }
  }
  if ((psVar4[3] & 0x2000U) != 0) {
    if ((*(byte *)(iVar8 + 0x27a) & 2) != 0) {
      *psVar4 = *psVar4 + (ushort)DAT_803dc070 * 0x100;
      sVar2 = *(short *)(iVar8 + 0x278) - (ushort)DAT_803dc070;
      *(short *)(iVar8 + 0x278) = sVar2;
      if (sVar2 < 0) {
        FUN_80006824((uint)psVar4,0x56);
        uVar7 = FUN_80017760(0xf0,300);
        *(short *)(iVar8 + 0x278) = (short)uVar7;
      }
    }
    if (*(int *)(psVar4 + 0x62) != 0) {
      iVar5 = *(int *)(psVar4 + 0x32);
      if (iVar5 != 0) {
        *(uint *)(iVar5 + 0x30) = *(uint *)(iVar5 + 0x30) | 0x1000;
      }
      (*(code *)(*DAT_803dd728 + 0x20))(psVar4,iVar8);
      goto LAB_80173f80;
    }
    iVar6 = *(int *)(psVar4 + 0x32);
    if (iVar6 != 0) {
      *(uint *)(iVar6 + 0x30) = *(uint *)(iVar6 + 0x30) & 0xffffefff;
    }
    *(undefined *)(iVar8 + 0x25b) = 1;
    fVar1 = lbl_803E4154;
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * lbl_803E4154;
      *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
      param_2 = (double)lbl_803E4158;
      *(float *)(psVar4 + 0x14) =
           -(float)(param_2 * (double)lbl_803DC074 - (double)*(float *)(psVar4 + 0x14));
    }
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) - lbl_803DC074;
    bVar3 = *(byte *)(iVar8 + 0x27a);
    if ((bVar3 & 1) == 0) {
      if ((bVar3 & 4) == 0) {
        if ((double)*(float *)(iVar8 + 0x26c) <= (double)lbl_803E415C) {
          FUN_80017ac8((double)*(float *)(iVar8 + 0x26c),param_2,param_3,param_4,param_5,param_6,
                       param_7,param_8,(int)psVar4);
        }
        goto LAB_80173f80;
      }
      if (*(float *)(iVar8 + 0x26c) <= lbl_803E415C) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfb;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
        *(float *)(iVar8 + 0x26c) = lbl_803E414C;
        (*(code *)(*DAT_803dd6f8 + 0x18))(psVar4);
        if (*(int *)(psVar4 + 0x18) == 0) {
          for (local_27[0] = '\x1e'; local_27[0] != '\0'; local_27[0] = local_27[0] + -1) {
            in_r7 = 0xffffffff;
            in_r8 = local_27;
            in_r9 = *DAT_803dd708;
            (*(code *)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1);
          }
        }
        *(undefined *)(psVar4 + 0x1b) = 1;
        FUN_80006824((uint)psVar4,0x57);
      }
      param_3 = (double)(*(float *)(psVar4 + 0x16) * lbl_803DC074);
      FUN_80017a88((double)(*(float *)(psVar4 + 0x12) * lbl_803DC074),
                   (double)(*(float *)(psVar4 + 0x14) * lbl_803DC074),param_3,(int)psVar4);
    }
    else {
      if (*(float *)(iVar8 + 0x26c) <= lbl_803E415C) {
        *(byte *)(iVar8 + 0x27a) = bVar3 & 0xfe;
        *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 4;
        *(float *)(iVar8 + 0x26c) = lbl_803E4160;
        *(undefined *)(psVar4 + 0x1b) = 0xff;
      }
      if (*(int *)(psVar4 + 0x18) == 0) {
        (*(code *)(*DAT_803dd708 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1,0xffffffff,0);
        in_r7 = 0xffffffff;
        in_r8 = (char *)0x0;
        in_r9 = *DAT_803dd708;
        (*(code *)(in_r9 + 8))(psVar4,*(undefined2 *)(iVar8 + 0x270),0,1);
      }
    }
    if ((*(byte *)(iVar8 + 0x27a) & 3) == 0) {
      (*(code *)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,psVar4,iVar8);
      (*(code *)(*DAT_803dd728 + 0x14))(psVar4,iVar8);
      (*(code *)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,psVar4,iVar8);
      if (*(char *)(iVar8 + 0x261) != '\0') {
        param_3 = -(double)*(float *)(psVar4 + 0x16);
        dVar9 = FUN_80293900((double)(float)(param_3 * param_3 +
                                            (double)(-*(float *)(psVar4 + 0x12) *
                                                     -*(float *)(psVar4 + 0x12) +
                                                    -*(float *)(psVar4 + 0x14) *
                                                    -*(float *)(psVar4 + 0x14))));
        if ((double)lbl_803E4164 < dVar9) {
          FUN_80006824((uint)psVar4,0x16b);
        }
        if (*(float *)(iVar8 + 0x6c) < lbl_803E4168) {
          *(float *)(psVar4 + 0x12) = -*(float *)(psVar4 + 0x12);
          *(float *)(psVar4 + 0x16) = -*(float *)(psVar4 + 0x16);
          fVar1 = lbl_803E4170;
          *(float *)(psVar4 + 0x12) = *(float *)(psVar4 + 0x12) * lbl_803E4170;
          *(float *)(psVar4 + 0x16) = *(float *)(psVar4 + 0x16) * fVar1;
        }
        else {
          *(float *)(psVar4 + 0x14) = -*(float *)(psVar4 + 0x14);
          *(float *)(psVar4 + 0x14) = *(float *)(psVar4 + 0x14) * lbl_803E416C;
        }
        bVar3 = *(char *)(iVar8 + 0x27b) + 1;
        *(byte *)(iVar8 + 0x27b) = bVar3;
        if (5 < bVar3) {
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 2;
          fVar1 = lbl_803E415C;
          *(float *)(psVar4 + 0x12) = lbl_803E415C;
          *(float *)(psVar4 + 0x14) = fVar1;
          *(float *)(psVar4 + 0x16) = fVar1;
        }
      }
    }
  }
  if (((*(byte *)(iVar8 + 0x27a) & 0x20) == 0) && ((*(byte *)(iVar8 + 0x27a) & 0x40) == 0)) {
    fVar1 = *(float *)(psVar4 + 8) - *(float *)(iVar5 + 0x10);
    if (fVar1 < lbl_803E415C) {
      fVar1 = -fVar1;
    }
    if (fVar1 < lbl_803E4174) {
      dVar9 = FUN_80017708((float *)(psVar4 + 0xc),(float *)(iVar5 + 0x18));
      dVar10 = (double)lbl_803E4178;
      fVar1 = (float)(dVar10 + (double)*(float *)(iVar8 + 0x268));
      if ((dVar9 < (double)(fVar1 * fVar1)) && (uVar7 = FUN_80294c78(iVar5), uVar7 != 0)) {
        uVar7 = FUN_80017690(0x90d);
        if (uVar7 == 0) {
          *(undefined2 *)(iVar8 + 0x280) = 0xffff;
          ObjMsg_SendToObject(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x7000a,
                       (uint)psVar4,iVar8 + 0x280,in_r7,in_r8,in_r9,in_r10);
          ObjHits_DisableObject((int)psVar4);
          FUN_80017698(0x90d,1);
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x20;
        }
        else {
          iVar6 = *(int *)(*(int *)(psVar4 + 0x28) + 0x18);
          (*(code *)(*DAT_803dd6f8 + 0x18))(psVar4);
          FUN_80081118((double)lbl_803E4148,psVar4,(uint)*(byte *)(iVar8 + 0x27c),0x28);
          ObjHits_DisableObject((int)psVar4);
          FUN_80006824((uint)psVar4,*(ushort *)(iVar8 + 0x274));
          FUN_80006810((int)psVar4,0x56);
          FUN_80294d40(iVar5,(int)*(char *)(iVar6 + 0xb));
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) & 0xfa;
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 8;
          *(byte *)(iVar8 + 0x27a) = *(byte *)(iVar8 + 0x27a) | 0x40;
          *(float *)(iVar8 + 0x26c) = lbl_803E414C;
          FUN_800723a0();
          *(undefined *)(psVar4 + 0x1b) = 1;
        }
      }
    }
  }
LAB_80173f80:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: magicdust_init
 * EN v1.0 Address: 0x80173B84
 * EN v1.0 Size: 1112b
 * EN v1.1 Address: 0x80173F98
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void magicdust_init(int param_1,int param_2)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  undefined local_58 [4];
  undefined2 local_54 [2];
  undefined2 local_50 [4];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  local_58[0] = 3;
  local_50[0] = DAT_803e4140;
  local_54[0] = DAT_803e4144;
  uVar3 = FUN_80017760(0,0xffff);
  uStack_44 = FUN_80017760(0x27,0x2c);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  dVar7 = (double)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4198) /
                  lbl_803E417C);
  uStack_3c = uVar3 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar6 = (double)FUN_80293f90();
  *(float *)(param_1 + 0x24) = (float)(dVar7 * dVar6);
  dVar6 = (double)FUN_80294964();
  *(float *)(param_1 + 0x2c) = (float)(dVar7 * dVar6);
  uStack_34 = FUN_80017760(0x28,0x32);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x28) =
       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4198) / lbl_803E4188;
  sVar1 = *(short *)(param_2 + 0x2e);
  if (sVar1 == 1) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
  }
  else if (sVar1 == 2) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    if (*(int *)(param_1 + 0x54) != 0) {
      ObjHits_DisableObject(param_1);
    }
    iVar4 = FUN_80017a98();
    fVar2 = lbl_803E418C;
    *(float *)(param_1 + 0x24) =
         (*(float *)(iVar4 + 0xc) - *(float *)(param_1 + 0xc)) / lbl_803E418C;
    *(float *)(param_1 + 0x28) = (*(float *)(iVar4 + 0x10) - *(float *)(param_1 + 0x10)) / fVar2;
    *(float *)(param_1 + 0x2c) = (*(float *)(iVar4 + 0x14) - *(float *)(param_1 + 0x14)) / fVar2;
  }
  else if (sVar1 == 3) {
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 1;
    *(undefined *)(param_1 + 0x36) = 1;
    uStack_34 = FUN_80017760(0x8c,0x96);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(param_1 + 0x28) =
         -((float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e4198) / lbl_803E4188);
  }
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x26);
  if (*(char *)(*(int *)(param_1 + 0x50) + 0x55) <= *(char *)(param_1 + 0xad)) {
    *(undefined *)(param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 100) != 0) {
    *(undefined *)(*(int *)(param_1 + 100) + 0x3a) = 100;
    *(undefined *)(*(int *)(param_1 + 100) + 0x3b) = 0x96;
  }
  iVar4 = FUN_80017a54(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x2cd) {
    uVar3 = FUN_80017760(0,1);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(undefined *)((int)local_54 + uVar3);
    *(undefined2 *)(iVar5 + 0x272) = 0x54e;
    *(undefined2 *)(iVar5 + 0x270) = 0x54a;
    *(undefined2 *)(iVar5 + 0x274) = 0x59;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b1;
    *(undefined *)(iVar5 + 0x27c) = 1;
  }
  else {
    if (sVar1 < 0x2cd) {
      if (sVar1 == 0x2c4) {
        uVar3 = FUN_80017760(0,1);
        *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = *(undefined *)((int)local_50 + uVar3);
        *(undefined2 *)(iVar5 + 0x272) = 0x54f;
        *(undefined2 *)(iVar5 + 0x270) = 0x54b;
        *(undefined2 *)(iVar5 + 0x274) = 0x58;
        *(undefined2 *)(iVar5 + 0x276) = 0x5b0;
        *(undefined *)(iVar5 + 0x27c) = 4;
        goto LAB_80174324;
      }
    }
    else if ((sVar1 != 0x2cf) && (sVar1 < 0x2cf)) {
      *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 3;
      *(undefined2 *)(iVar5 + 0x272) = 0x54d;
      *(undefined2 *)(iVar5 + 0x270) = 0x549;
      *(undefined2 *)(iVar5 + 0x274) = 0x5a;
      *(undefined2 *)(iVar5 + 0x276) = 0x5b2;
      *(undefined *)(iVar5 + 0x27c) = 2;
      goto LAB_80174324;
    }
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = 2;
    *(undefined2 *)(iVar5 + 0x272) = 0x550;
    *(undefined2 *)(iVar5 + 0x270) = 0x54c;
    *(undefined2 *)(iVar5 + 0x274) = 0x5b;
    *(undefined2 *)(iVar5 + 0x276) = 0x5b3;
    *(undefined *)(iVar5 + 0x27c) = 6;
  }
LAB_80174324:
  *(float *)(iVar5 + 0x268) = lbl_803E4190;
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    (*(code *)(*DAT_803dd728 + 4))(iVar5,0,0x40007,0);
    (*(code *)(*DAT_803dd728 + 0xc))(iVar5,1,&DAT_80321908,iVar5 + 0x268,local_58);
    (*(code *)(*DAT_803dd728 + 0x20))(param_1,iVar5);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  if ((*(byte *)(iVar5 + 0x27a) & 1) == 0) {
    *(float *)(iVar5 + 0x26c) = lbl_803E4160;
    *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 4;
  }
  else {
    *(float *)(iVar5 + 0x26c) = lbl_803E4194;
  }
  ObjMsg_AllocQueue(param_1,1);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80173fdc
 * EN v1.0 Address: 0x80173FDC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017443C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173fdc(int param_1)
{
  FUN_80017a70(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80173ffc
 * EN v1.0 Address: 0x80173FFC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017445C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80173ffc(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80174024
 * EN v1.0 Address: 0x80174024
 * EN v1.0 Size: 856b
 * EN v1.1 Address: 0x80174490
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80174024(int param_1)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *unaff_r31;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  int local_e8;
  int local_e4 [3];
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  if (((int)*(uint *)(param_1 + 0xf8) < 0) ||
     (uVar2 = FUN_80017690(*(uint *)(param_1 + 0xf8)), *(byte *)(iVar5 + 0x1f) != uVar2)) {
    local_e4[2] = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_e4[1] = 0x43300000;
    dVar7 = (double)FUN_80294964();
    uStack_d4 = (uint)*(byte *)(iVar5 + 0x18) * -0x100 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar8 = (double)FUN_80293f90();
    uStack_cc = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar9 = (double)FUN_80294964();
    uStack_c4 = (uint)*(byte *)(iVar5 + 0x19) * -0x100 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar10 = (double)FUN_80293f90();
    uStack_bc = (uint)*(byte *)(iVar5 + 0x1a);
    local_c0 = 0x43300000;
    dVar16 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1a)) -
                            DOUBLE_803e41b8);
    uStack_b4 = (uint)*(byte *)(iVar5 + 0x1b) << 1 ^ 0x80000000;
    local_b8 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e41b0);
    uStack_ac = (uint)*(byte *)(iVar5 + 0x1c);
    local_b0 = 0x43300000;
    dVar14 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x1c)) -
                            DOUBLE_803e41b8);
    bVar1 = *(byte *)(iVar5 + 0x22);
    if (bVar1 == 1) {
      local_e4[0] = FUN_80017a90();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if (bVar1 == 0) {
      local_e4[0] = FUN_80017a98();
      if (local_e4[0] == 0) {
        return;
      }
      unaff_r31 = local_e4;
      local_e8 = 1;
    }
    else if ((bVar1 < 3) && (unaff_r31 = ObjGroup_GetObjects(5,&local_e8), unaff_r31 == (int *)0x0)) {
      return;
    }
    dVar18 = -dVar16;
    dVar17 = -dVar14;
    for (iVar4 = 0; iVar4 < local_e8; iVar4 = iVar4 + 1) {
      iVar3 = *unaff_r31;
      dVar11 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(param_1 + 0xc));
      dVar12 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10));
      dVar13 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(param_1 + 0x14));
      dVar6 = (double)(float)(dVar11 * dVar7 + (double)(float)(dVar13 * dVar8));
      if ((((dVar18 < dVar6) && (dVar6 < dVar16)) &&
          (dVar6 = (double)(float)(-dVar12 * dVar10 +
                                  (double)(float)((double)(float)(-dVar11 * dVar8 +
                                                                 (double)(float)(dVar13 * dVar7)) *
                                                 dVar9)), dVar17 < dVar6)) &&
         (((dVar6 < dVar14 &&
           (dVar6 = (double)(float)(dVar12 * dVar9 + (double)(float)(dVar6 * dVar10)),
           (double)lbl_803E41AC <= dVar6)) && (dVar6 < dVar15)))) {
        bVar1 = *(byte *)(iVar5 + 0x22);
        if (bVar1 != 1) {
          if (bVar1 == 0) {
            uStack_ac = (uint)*(byte *)(iVar5 + 0x1d);
            local_b0 = 0x43300000;
            FUN_80294bd4((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e41b8),
                         iVar3,1);
          }
          else if (bVar1 < 3) {
            (*(code *)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,*(undefined *)(iVar5 + 0x1d));
          }
        }
      }
      unaff_r31 = unaff_r31 + 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017437c
 * EN v1.0 Address: 0x8017437C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80174864
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017437c(int param_1,int param_2)
{
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_80017a74(param_1);
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  if (*(short *)(param_2 + 0x20) < 0) {
    *(undefined4 *)(param_1 + 0xf8) = 0xffffffff;
  }
  else {
    *(int *)(param_1 + 0xf8) = (int)*(short *)(param_2 + 0x20);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801743f0
 * EN v1.0 Address: 0x801743F0
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801748E4
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801743f0(uint param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_80017a98();
  if (((*(ushort *)(param_2 + 0x100) & 0x80) == 0) && (uVar2 = FUN_80294bd8(iVar1,10), uVar2 == 0))
  {
    FUN_80006824(param_1,0x66);
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 2;
    if ((*(ushort *)(param_2 + 0x100) & 4) == 0) {
      FUN_8017504c();
    }
    if (*(float *)(param_1 + 0xc) <= lbl_803E41C4 + *(float *)(iVar3 + 8)) {
      FUN_80017698((int)*(short *)(param_2 + 0xac),1);
      *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
      *(float *)(param_1 + 0xc) = (float)((double)*(float *)(iVar3 + 8) - DOUBLE_803e41c8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(float *)(param_1 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar3 + 0x10));
      FUN_80006824(param_1,0x68);
    }
    uVar2 = FUN_80017690(0xa1a);
    if (uVar2 != 0) {
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar3 + 0x10);
    }
  }
  else {
    FUN_8000680c(param_1,8);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80174524
 * EN v1.0 Address: 0x80174524
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x80174A34
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80174524(int param_1,int param_2)
{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar3 = *(int *)(iVar4 + 0x14);
  if (iVar3 == 0x49b5d) {
    *(undefined *)(param_2 + 0x144) = 0xb;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  else if (iVar3 < 0x49b5d) {
    if (iVar3 == 0x49b2c) {
      *(undefined *)(param_2 + 0x144) = 10;
    }
  }
  else if (iVar3 < 0x49b5f) {
    *(undefined *)(param_2 + 0x144) = 0xc;
    *(undefined *)(param_1 + 0xad) = 1;
  }
  uVar1 = FUN_80017690((int)*(short *)(iVar4 + 0x18));
  if (uVar1 != 0) {
    *(ushort *)(param_2 + 0x100) = *(ushort *)(param_2 + 0x100) | 0x80;
    puVar2 = (undefined4 *)FUN_80039520(param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  return;
}

extern void fn_8002B758(void);

/*
 * --INFO--
 *
 * Function: effectbox_free
 * EN v1.0 Address: 0x80173F90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void effectbox_free(void)
{
  fn_8002B758();
}


/* Trivial 4b 0-arg blr leaves. */
void effectbox_hitDetect(void) {}
void effectbox_release(void) {}
void effectbox_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_func08(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E3508;
extern void fn_8003B8F4(f32);
#pragma peephole off
void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3508); }
#pragma peephole reset
