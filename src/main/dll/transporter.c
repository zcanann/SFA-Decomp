#include "ghidra_import.h"
#include "main/dll/transporter.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_80006904();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_800178b8();
extern ushort FUN_80017934();
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_AddContactObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();
extern int ObjList_ContainsObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053c98();
extern int FUN_80056600();
extern int FUN_800620e8();
extern char FUN_800632f4();
extern int FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_8007f358();
extern int FUN_8007f3c8();
extern undefined4 FUN_800e82e0();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_80135810();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern undefined4 FUN_801743f0();
extern undefined4 FUN_80174524();
extern int FUN_80174a80();
extern undefined4 FUN_80174ed4();
extern undefined4 FUN_8017504c();
extern undefined4 FUN_80175468();
extern int FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294bd8();
extern byte FUN_80294c20();
extern int FUN_80294c54();
extern uint FUN_80294d30();

extern undefined4 DAT_802c29f0;
extern undefined4 DAT_802c29f4;
extern undefined4 DAT_802c29f8;
extern undefined4 DAT_802c29fc;
extern undefined4 DAT_803ad340;
extern undefined4 DAT_803ad3e0;
extern undefined4 DAT_803ad3e4;
extern undefined4 DAT_803ad3e8;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803de738;
extern f64 DOUBLE_803e41c8;
extern f64 DOUBLE_803e41d0;
extern f64 DOUBLE_803e4210;
extern f64 DOUBLE_803e4268;
extern f64 DOUBLE_803e4278;
extern f64 DOUBLE_803e4290;
extern f64 DOUBLE_803e42a8;
extern f32 lbl_803DC074;
extern f32 lbl_803E41C0;
extern f32 lbl_803E41D8;
extern f32 lbl_803E41F0;
extern f32 lbl_803E4220;
extern f32 lbl_803E4224;
extern f32 lbl_803E4234;
extern f32 lbl_803E4238;
extern f32 lbl_803E423C;
extern f32 lbl_803E4240;
extern f32 lbl_803E4244;
extern f32 lbl_803E4248;
extern f32 lbl_803E424C;
extern f32 lbl_803E4250;
extern f32 lbl_803E4254;
extern f32 lbl_803E4258;
extern f32 lbl_803E425C;
extern f32 lbl_803E4260;
extern f32 lbl_803E4264;
extern f32 lbl_803E4270;
extern f32 lbl_803E4274;
extern f32 lbl_803E4284;
extern f32 lbl_803E4288;
extern f32 lbl_803E428C;
extern f32 lbl_803E4298;
extern f32 lbl_803E429C;
extern f32 lbl_803E42A0;
extern f32 lbl_803E42A4;
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
/*
 * --INFO--
 *
 * Function: FUN_801755cc
 * EN v1.0 Address: 0x801755CC
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801758D4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801755cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  undefined4 *local_28;
  uint local_24;
  uint local_20 [5];
  
  iVar2 = *(int *)(param_9 + 0xb8);
  local_28 = (undefined4 *)0x0;
  while (iVar1 = ObjMsg_Pop(param_9,&local_24,local_20,(uint *)&local_28), iVar1 != 0) {
    if (local_24 == 0x40001) {
      if (*(short *)(param_9 + 0x46) == 0x21e) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
      if (*(short *)(param_9 + 0x46) == 0x411) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
    }
    else if ((int)local_24 < 0x40001) {
      if (((local_24 == 0xe) && (*(short *)(param_9 + 0x46) != 0x21e)) &&
         (*(short *)(param_9 + 0x46) != 0x411)) {
        param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               param_9);
      }
    }
    else if (local_24 == 0xf0003) {
      *(uint *)(iVar2 + 0xb8) = local_20[0];
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80175740
 * EN v1.0 Address: 0x80175740
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801759F8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80175740(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 0xc);
  fVar2 = *(float *)(param_2 + 0x10) - *(float *)(param_1 + 0x10);
  fVar3 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 0x14);
  dVar5 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  return ((uint)(byte)((dVar5 < (double)*(float *)(iVar4 + 0xc)) << 3) << 0x1c) >> 0x1f;
}

/*
 * --INFO--
 *
 * Function: FUN_801757ac
 * EN v1.0 Address: 0x801757AC
 * EN v1.0 Size: 1832b
 * EN v1.1 Address: 0x80175A78
 * EN v1.1 Size: 2300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801757ac(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)
{
  bool bVar1;
  short sVar2;
  ushort uVar3;
  float fVar4;
  float fVar5;
  int *piVar6;
  int iVar7;
  byte bVar9;
  uint uVar8;
  ushort *puVar10;
  int iVar11;
  float *pfVar12;
  int iVar13;
  float *pfVar14;
  int iVar15;
  double dVar16;
  double extraout_f1;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  float fStack_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  float local_198;
  uint auStack_194 [6];
  ushort local_17c [4];
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164 [12];
  float local_134 [12];
  float afStack_104 [32];
  float local_84 [4];
  undefined local_74;
  undefined local_70;
  undefined2 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar18 = FUN_80286834();
  piVar6 = (int *)((ulonglong)uVar18 >> 0x20);
  puVar10 = (ushort *)uVar18;
  dVar17 = extraout_f1;
  iVar7 = FUN_80017a98();
  iVar15 = piVar6[0x2e];
  iVar11 = 5;
  iVar13 = iVar15 + 0x14;
  while( true ) {
    bVar1 = iVar11 == 0;
    iVar11 = iVar11 + -1;
    if (bVar1) break;
    *(undefined4 *)(iVar13 + 0x114) = *(undefined4 *)(iVar13 + 0x110);
    *(undefined4 *)(iVar13 + 0x128) = *(undefined4 *)(iVar13 + 0x124);
    iVar13 = iVar13 + -4;
  }
  *(int *)(iVar15 + 0x118) = piVar6[3];
  *(int *)(iVar15 + 300) = piVar6[5];
  local_1a0 = *(float *)(puVar10 + 6);
  local_19c = lbl_803E4234 + *(float *)(puVar10 + 8);
  local_198 = *(float *)(puVar10 + 10);
  local_84[0] = lbl_803E4238;
  local_74 = 0xff;
  local_70 = 3;
  local_58 = 0;
  iVar13 = 0;
  dVar16 = (double)lbl_803E41C0;
  if (dVar17 <= dVar16) {
    if (param_2 <= dVar16) {
      if (param_2 < dVar16) {
        uStack_44 = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_48 = 0x43300000;
        dVar16 = (double)FUN_80293f90();
        local_1ac = (float)((double)lbl_803E423C * dVar16 + (double)local_1a0);
        local_1a8 = local_19c;
        uStack_4c = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        local_1a4 = (float)((double)lbl_803E423C * dVar16 + (double)local_198);
        trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
        FUN_80063a74(0,auStack_194,0x208,'\x01');
        iVar13 = FUN_80063a68();
        if (iVar13 == 0) {
          iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,
                                0xff,0);
        }
        if (iVar13 != 0) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
          fVar4 = lbl_803E41C0;
          *(float *)(iVar15 + 0x108) = lbl_803E41C0;
          *(float *)(iVar15 + 0x10c) = fVar4;
        }
      }
    }
    else {
      uStack_44 = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_48 = 0x43300000;
      dVar16 = (double)FUN_80293f90();
      local_1ac = (float)((double)lbl_803E423C * dVar16 + (double)local_1a0);
      local_1a8 = local_19c;
      uStack_4c = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_50 = 0x43300000;
      dVar16 = (double)FUN_80294964();
      local_1a4 = (float)((double)lbl_803E423C * dVar16 + (double)local_198);
      trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
      FUN_80063a74(0,auStack_194,0x208,'\x01');
      iVar13 = FUN_80063a68();
      if (iVar13 == 0) {
        iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff
                              ,0);
      }
      if (iVar13 != 0) {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        fVar4 = lbl_803E41C0;
        *(float *)(iVar15 + 0x108) = lbl_803E41C0;
        *(float *)(iVar15 + 0x10c) = fVar4;
      }
    }
  }
  else {
    uStack_4c = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar16 = (double)FUN_80293f90();
    local_1ac = (float)((double)lbl_803E4238 * dVar16 + (double)local_1a0);
    local_1a8 = local_19c;
    uStack_44 = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar16 = (double)FUN_80294964();
    local_1a4 = (float)((double)lbl_803E4238 * dVar16 + (double)local_198);
    trackDolphin_buildSweptBounds(auStack_194,&local_1a0,&local_1ac,local_84,1);
    FUN_80063a74(0,auStack_194,0x208,'\x01');
    iVar13 = FUN_80063a68();
    if (iVar13 == 0) {
      iVar13 = FUN_800620e8(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff,0
                           );
    }
    if (iVar13 != 0) {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
      fVar4 = lbl_803E41C0;
      *(float *)(iVar15 + 0x108) = lbl_803E41C0;
      *(float *)(iVar15 + 0x10c) = fVar4;
    }
  }
  bVar9 = FUN_80294c20(iVar7);
  if ((bVar9 == 0) && ((*(byte *)(iVar15 + 0x114) >> 6 & 1) == 0)) {
    iVar13 = 1;
    dVar16 = (double)lbl_803E41C0;
    if (dVar17 <= dVar16) {
      if (dVar16 <= dVar17) {
        if (param_2 <= dVar16) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
        }
        else {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        }
      }
      else {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x100;
      }
    }
    else {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
    }
    fVar4 = lbl_803E41C0;
    *(float *)(iVar15 + 0x108) = lbl_803E41C0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  if ((param_5 == 0) || ((*(ushort *)(iVar15 + 0x100) & 8) != 0)) {
    iVar7 = piVar6[0x16];
    bVar9 = *(byte *)(iVar7 + 0x10c);
    iVar13 = iVar15;
    for (iVar11 = 0; iVar11 < *(char *)(iVar15 + 0xb4); iVar11 = iVar11 + 1) {
      FUN_80017778((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                   (double)*(float *)(iVar13 + 0x20),(float *)(iVar7 + (bVar9 + 2) * 0x40),
                   (float *)(iVar13 + 0x78),(float *)(iVar13 + 0x7c),(float *)(iVar13 + 0x80));
      iVar13 = iVar13 + 0xc;
    }
    goto LAB_801762c4;
  }
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 2;
  *(char *)(iVar15 + 0x115) = *(char *)(iVar15 + 0x115) + -1;
  if (*(char *)(iVar15 + 0x115) < '\x01') {
    uVar8 = randomGetRange(0x28,0x3c);
    *(char *)(iVar15 + 0x115) = (char)uVar8;
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x20;
  }
  fVar4 = lbl_803E41C0;
  if ((*(ushort *)(iVar15 + 0x100) & 0x80) == 0) {
    if (iVar13 == 0) {
      *(float *)(iVar15 + 0x108) = (float)dVar17;
      *(float *)(iVar15 + 0x10c) = (float)param_2;
    }
  }
  else {
    *(float *)(iVar15 + 0x108) = lbl_803E41C0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  *(int *)(iVar15 + 0x140) = (int)(short)*puVar10;
  local_17c[0] = *puVar10;
  local_17c[1] = 0;
  local_17c[2] = 0;
  local_174 = lbl_803E4220;
  local_170 = lbl_803E41C0;
  local_16c = lbl_803E41C0;
  local_168 = lbl_803E41C0;
  FUN_80017754(afStack_104,local_17c);
  FUN_80017778((double)*(float *)(iVar15 + 0x10c),(double)lbl_803E41C0,
               (double)*(float *)(iVar15 + 0x108),afStack_104,(float *)(piVar6 + 9),&fStack_1b0,
               (float *)(piVar6 + 0xb));
  *(byte *)(iVar15 + 0x114) = *(byte *)(iVar15 + 0x114) & 0x7f | 0x80;
  FUN_80017a88((double)(float)piVar6[9],(double)lbl_803E41C0,(double)(float)piVar6[0xb],
               (int)piVar6);
  FUN_80006904();
  pfVar12 = local_134;
  pfVar14 = local_164;
  iVar13 = iVar15;
  for (iVar7 = 0; iVar7 < *(char *)(iVar15 + 0xb4); iVar7 = iVar7 + 1) {
    FUN_800068f8((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                 (double)*(float *)(iVar13 + 0x20),pfVar12,pfVar12 + 1,pfVar12 + 2,(int)piVar6);
    *pfVar14 = (float)piVar6[3] - *pfVar12;
    pfVar14[1] = (float)piVar6[4] - pfVar12[1];
    pfVar14[2] = (float)piVar6[5] - pfVar12[2];
    pfVar12 = pfVar12 + 3;
    iVar13 = iVar13 + 0xc;
    pfVar14 = pfVar14 + 3;
  }
  if ((*(ushort *)(iVar15 + 0x100) & 4) == 0) {
    FUN_8017504c();
  }
  FUN_80006904();
  if ((lbl_803E41C0 != *(float *)(iVar15 + 0x108)) ||
     (lbl_803E41C0 != *(float *)(iVar15 + 0x10c))) {
    iVar13 = piVar6[0x13];
    uVar3 = *(ushort *)(piVar6[0x2e] + 0x100);
    if ((uVar3 & 1) != 0) {
      *(ushort *)(piVar6[0x2e] + 0x100) = uVar3 & 0xfffe;
      uVar8 = (uint)*(short *)(iVar13 + 0x18);
      if (-1 < (int)uVar8) {
        sVar2 = *(short *)((int)piVar6 + 0x46);
        if (sVar2 != 0x411) {
          if (sVar2 < 0x411) {
            if (sVar2 != 0x21e) {
LAB_801761f4:
              if (-1 < *(char *)(iVar13 + 0x23)) {
                FUN_80017698(uVar8,0);
              }
            }
          }
          else if (sVar2 != 0x7df) goto LAB_801761f4;
        }
      }
    }
  }
  fVar4 = (float)piVar6[3] - *(float *)(iVar15 + 0x128);
  fVar5 = (float)piVar6[5] - *(float *)(iVar15 + 0x13c);
  if ((lbl_803E4220 < fVar4 * fVar4 + fVar5 * fVar5) &&
     ((*(ushort *)(iVar15 + 0x100) & 0x20) != 0)) {
    FUN_80006824((uint)piVar6,100);
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & 0xffdf;
  }
LAB_801762c4:
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & 0xf0ff;
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80175ed4
 * EN v1.0 Address: 0x80175ED4
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80176374
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80175ed4(int param_1)
{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x411) {
    FUN_80017698((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((sVar1 < 0x411) && (sVar1 == 0x21e)) {
    FUN_80017698((int)*(short *)(iVar2 + 0xac),0);
  }
  else if ((((-1 < *(short *)(iVar3 + 0x18)) && (sVar1 != 0x54a)) && (sVar1 != 0x5ae)) &&
          ((sVar1 != 0x108 && (*(char *)(iVar2 + 0x146) != '\0')))) {
    FUN_800e8630(param_1);
  }
  if ((*(ushort *)(iVar2 + 0x100) & 1) != 0) {
    iVar2 = DAT_803de738 * 4;
    DAT_803de738 = DAT_803de738 + 1;
    *(undefined4 *)(&DAT_803ad340 + iVar2) = *(undefined4 *)(iVar3 + 0x14);
  }
  ObjGroup_RemoveObject(param_1,5);
  return;
}

/*
 * --INFO--
 *
 * Function: pushable_render
 * EN v1.0 Address: 0x80175FB8
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x80176464
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void pushable_render(void)
{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  char in_r8;
  
  iVar3 = FUN_80286840();
  fVar2 = lbl_803E41C0;
  if (in_r8 == '\0') goto LAB_80176578;
  iVar4 = *(int *)(iVar3 + 0xb8);
  sVar1 = *(short *)(iVar3 + 0x46);
  if (sVar1 == 0x411) {
    uVar5 = FUN_80017690((int)*(short *)(iVar4 + 0xac));
joined_r0x801764e4:
    if (uVar5 != 0) goto LAB_80176578;
  }
  else if (sVar1 < 0x411) {
    if (sVar1 == 0x21e) {
      uVar5 = FUN_80017690((int)*(short *)(iVar4 + 0xac));
      goto joined_r0x801764e4;
    }
  }
  else if ((sVar1 == 0x54a) && (lbl_803E41C0 < *(float *)(iVar4 + 0x14))) {
    *(float *)(iVar4 + 0x14) = *(float *)(iVar4 + 0x14) - lbl_803DC074;
    if (fVar2 < *(float *)(iVar4 + 0x14)) {
      FUN_8003b540(200,0,0,0xff);
    }
    else {
      *(float *)(iVar4 + 0x14) = fVar2;
    }
  }
  iVar4 = **(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
  *(ushort *)(iVar4 + 2) = *(ushort *)(iVar4 + 2) | 2;
  FUN_8003b818(iVar3);
LAB_80176578:
  FUN_8028688c();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801760a4
 * EN v1.0 Address: 0x801760A4
 * EN v1.0 Size: 1316b
 * EN v1.1 Address: 0x80176590
 * EN v1.1 Size: 1540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801760a4(void)
{
  float fVar1;
  short sVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  char cVar8;
  int iVar7;
  float *pfVar9;
  int iVar10;
  float *pfVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  float *pfVar15;
  double dVar16;
  double in_f31;
  double in_ps31_1;
  float local_128;
  int local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110 [4];
  ushort local_100;
  undefined2 local_fe;
  undefined2 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  uint uStack_e8;
  uint local_e4;
  uint local_d8;
  float afStack_d0 [16];
  float local_90 [12];
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar4 = FUN_8028682c();
  local_120 = DAT_802c29f0;
  local_11c = DAT_802c29f4;
  local_118 = DAT_802c29f8;
  local_114 = DAT_802c29fc;
  iVar5 = FUN_80017a98();
  iVar14 = *(int *)(iVar4 + 0xb8);
  *(float *)(iVar14 + 0x110) = *(float *)(iVar14 + 0x110) - lbl_803DC074;
  if (*(float *)(iVar14 + 0x110) <= lbl_803E41C0) {
    *(float *)(iVar14 + 0x110) = lbl_803E41C0;
  }
  if (-1 < *(char *)(iVar14 + 0x114)) {
    uVar6 = FUN_80294d30(iVar5);
    fVar1 = lbl_803E4244;
    if (uVar6 == 0xd) {
      fVar1 = lbl_803E4240;
    }
    *(float *)(iVar14 + 0x108) = *(float *)(iVar14 + 0x108) * fVar1;
    if ((*(float *)(iVar14 + 0x108) < lbl_803E4248) &&
       (lbl_803E424C < *(float *)(iVar14 + 0x108))) {
      *(float *)(iVar14 + 0x108) = lbl_803E41C0;
    }
    *(float *)(iVar14 + 0x10c) = *(float *)(iVar14 + 0x10c) * fVar1;
    if ((*(float *)(iVar14 + 0x10c) < lbl_803E4248) &&
       (lbl_803E424C < *(float *)(iVar14 + 0x10c))) {
      *(float *)(iVar14 + 0x10c) = lbl_803E41C0;
    }
    if ((lbl_803E41C0 != *(float *)(iVar14 + 0x108)) ||
       (lbl_803E41C0 != *(float *)(iVar14 + 0x10c))) {
      local_100 = (ushort)*(undefined4 *)(iVar14 + 0x140);
      local_fe = 0;
      local_fc = 0;
      local_f8 = lbl_803E4220;
      local_f4 = lbl_803E41C0;
      local_f0 = lbl_803E41C0;
      local_ec = lbl_803E41C0;
      FUN_80017754(afStack_d0,&local_100);
      FUN_80017778((double)*(float *)(iVar14 + 0x10c),(double)lbl_803E41C0,
                   (double)*(float *)(iVar14 + 0x108),afStack_d0,(float *)(iVar4 + 0x24),&local_128,
                   (float *)(iVar4 + 0x2c));
      FUN_80017a88((double)*(float *)(iVar4 + 0x24),(double)lbl_803E41C0,
                   (double)*(float *)(iVar4 + 0x2c),iVar4);
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        FUN_8017504c();
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 2;
    }
  }
  *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf | 0x40;
  sVar2 = *(short *)(iVar4 + 0x46);
  if (sVar2 == 0x411) {
    uVar6 = FUN_80017690((int)*(short *)(iVar14 + 0xac));
joined_r0x801767cc:
    if (uVar6 != 0) goto LAB_80176b74;
  }
  else {
    if (sVar2 < 0x411) {
      if (sVar2 == 0x21e) {
        uVar6 = FUN_80017690((int)*(short *)(iVar14 + 0xac));
      }
      else {
        if ((0x21d < sVar2) || (sVar2 != 0x108)) goto LAB_801767e4;
        uVar6 = FUN_80017690(0x272);
      }
      goto joined_r0x801767cc;
    }
    if (sVar2 == 0x85a) {
      *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf;
    }
  }
LAB_801767e4:
  if ((*(ushort *)(iVar14 + 0x100) & 4) != 0) {
    *(float *)(iVar4 + 0x28) = -(lbl_803E4250 * lbl_803DC074 - *(float *)(iVar4 + 0x28));
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x28) * lbl_803DC074 + *(float *)(iVar4 + 0x10);
  }
  if (((*(ushort *)(iVar14 + 0x100) & 2) != 0) || ((*(ushort *)(iVar14 + 0x100) & 4) != 0)) {
    FUN_80006904();
    pfVar15 = local_90;
    pfVar11 = pfVar15;
    iVar5 = iVar14;
    for (iVar10 = 0; iVar10 < *(char *)(iVar14 + 0xb4); iVar10 = iVar10 + 1) {
      FUN_800068f8((double)*(float *)(iVar5 + 0x48),(double)*(float *)(iVar5 + 0x4c),
                   (double)*(float *)(iVar5 + 0x50),pfVar11,pfVar11 + 1,pfVar11 + 2,iVar4);
      pfVar11 = pfVar11 + 3;
      iVar5 = iVar5 + 0xc;
    }
    trackDolphin_buildSweptBounds(&uStack_e8,(float *)(iVar14 + 0x78),local_90,&local_120,4);
    uStack_5c = local_e4 ^ 0x80000000;
    local_60 = 0x43300000;
    local_e4 = (uint)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e4210) -
                     lbl_803E4254);
    local_58 = (longlong)(int)local_e4;
    uStack_4c = local_d8 ^ 0x80000000;
    local_50 = 0x43300000;
    local_d8 = (uint)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4210) +
                     lbl_803E4254);
    local_48 = (double)(longlong)(int)local_d8;
    FUN_80063a74(iVar4,&uStack_e8,1,'\x01');
    local_128 = lbl_803E41C0;
    uVar12 = 0;
    uVar6 = 0;
    pfVar11 = local_110;
    for (iVar5 = 0; iVar5 < *(char *)(iVar14 + 0xb4); iVar5 = iVar5 + 1) {
      fVar1 = pfVar15[1];
      *pfVar11 = fVar1;
      in_f31 = (double)lbl_803E41C0;
      cVar8 = FUN_800632f4((double)*pfVar15,(double)fVar1,(double)pfVar15[2],iVar4,&local_124,-1,0);
      bVar3 = false;
      if (cVar8 != 0) {
        iVar10 = 0;
        for (iVar13 = 0; iVar13 < cVar8; iVar13 = iVar13 + 1) {
          pfVar9 = *(float **)(local_124 + iVar10);
          if (*(char *)(pfVar9 + 5) == '\x0e') {
            dVar16 = (double)(*pfVar9 - *(float *)(iVar4 + 0x10));
            if ((double)lbl_803E41C0 < dVar16) {
              in_f31 = (double)(float)(in_f31 + dVar16);
              uVar6 = uVar6 + 1;
            }
          }
          else if (!bVar3) {
            fVar1 = *pfVar9;
            if (((fVar1 < lbl_803E41F0 + pfVar15[1]) && (pfVar15[1] - lbl_803E4258 < fVar1)) &&
               (lbl_803E425C < pfVar9[2])) {
              *pfVar11 = fVar1;
              local_128 = local_128 + fVar1;
              iVar7 = *(int *)(*(int *)(local_124 + iVar10) + 0x10);
              if (iVar7 != 0) {
                ObjHits_AddContactObject(iVar7,iVar4);
              }
              uVar12 = uVar12 + 1;
              bVar3 = true;
            }
          }
          iVar10 = iVar10 + 4;
        }
      }
      pfVar15 = pfVar15 + 3;
      pfVar11 = pfVar11 + 1;
    }
    *(undefined4 *)(iVar14 + 0xf8) = *(undefined4 *)(iVar14 + 0xf4);
    if (uVar6 == 0) {
      *(float *)(iVar14 + 0xf4) = lbl_803E41C0;
    }
    else {
      local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      *(float *)(iVar14 + 0xf4) = (float)(in_f31 / (double)(float)(local_48 - DOUBLE_803e4210));
    }
    if ((uVar12 == 0) || (lbl_803E41C0 < *(float *)(iVar14 + 0x110))) {
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        *(float *)(iVar14 + 0x110) = lbl_803E4260;
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 0xc;
    }
    else {
      *(float *)(iVar4 + 0x28) = lbl_803E41C0;
      local_48 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
      *(float *)(iVar4 + 0x10) = lbl_803E4224 + local_128 / (float)(local_48 - DOUBLE_803e4210);
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) & 0xfff3;
    }
  }
  FUN_80006904();
  iVar5 = iVar14;
  for (iVar10 = 0; iVar10 < *(char *)(iVar14 + 0xb4); iVar10 = iVar10 + 1) {
    FUN_800068f8((double)*(float *)(iVar5 + 0x18),(double)*(float *)(iVar5 + 0x1c),
                 (double)*(float *)(iVar5 + 0x20),(float *)(iVar5 + 0x78),(float *)(iVar5 + 0x7c),
                 (float *)(iVar5 + 0x80),iVar4);
    iVar5 = iVar5 + 0xc;
  }
LAB_80176b74:
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801765c8
 * EN v1.0 Address: 0x801765C8
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x80176B94
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801765c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  short sVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  iVar6 = *(int *)(param_9 + 0xb8);
  *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) & 0xfffd;
  *(byte *)(iVar6 + 0x114) = *(byte *)(iVar6 + 0x114) & 0x7f;
  dVar7 = (double)lbl_803E41C0;
  if (dVar7 != (double)*(float *)(param_9 + 0x28)) {
    *(ushort *)(iVar6 + 0x100) = *(ushort *)(iVar6 + 0x100) | 2;
  }
  if ((*(byte *)(iVar6 + 0x114) >> 6 & 1) == 0) {
    iVar2 = FUN_80017a98();
    bVar4 = FUN_80294c20(iVar2);
    if (bVar4 != 0) goto LAB_80176c2c;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  else {
LAB_80176c2c:
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  if (((*(byte *)(param_9 + 0xaf) & 4) != 0) && (uVar3 = FUN_80017690(0x913), uVar3 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
    FUN_80017698(0x913,1);
    return;
  }
  iVar2 = FUN_80017a98();
  if (((iVar2 != 0) && (uVar3 = FUN_80294bd8(iVar2,10), uVar3 != 0)) ||
     ((*(ushort *)(iVar6 + 0x100) & 4) != 0)) {
    *(undefined *)(iVar6 + 0x145) = 0x78;
  }
  if (*(char *)(iVar6 + 0x145) == '\0') {
    if (*(char *)(iVar6 + 0x146) != '\0') {
      FUN_800e82e0(param_9);
    }
  }
  else {
    *(char *)(iVar6 + 0x145) = *(char *)(iVar6 + 0x145) + -1;
  }
  sVar1 = *(short *)(param_9 + 0x46);
  if (sVar1 == 0x411) {
    iVar5 = FUN_80174a80(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  else {
    if (0x410 < sVar1) {
      if (sVar1 == 0x54a) {
        uVar3 = FUN_80017690((int)*(short *)(iVar6 + 0xac));
        if (uVar3 != 0) {
          *(float *)(param_9 + 0xc) = (float)((double)*(float *)(iVar5 + 8) - DOUBLE_803e41c8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
          *(float *)(param_9 + 0x14) = (float)(DOUBLE_803e41d0 + (double)*(float *)(iVar5 + 0x10));
        }
        FUN_801743f0(param_9,iVar6);
      }
      goto LAB_80176e04;
    }
    if (sVar1 != 0x21e) {
      if ((sVar1 < 0x21e) && (sVar1 == 0x108)) {
        if ((lbl_803E41C0 == *(float *)(iVar6 + 0xf8)) &&
           (lbl_803E41C0 < *(float *)(iVar6 + 0xf4))) {
          FUN_80006824(param_9,0x68);
          FUN_80017698(0x272,1);
        }
        uVar3 = FUN_80017690(0x272);
        if (uVar3 != 0) {
          FUN_80017ad0(param_9);
          ObjHits_DisableObject(param_9);
          *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        }
      }
      goto LAB_80176e04;
    }
    iVar5 = FUN_80174a80(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6
                        );
  }
  if (iVar5 != 0) {
    return;
  }
LAB_80176e04:
  sVar1 = *(short *)(param_9 + 0x46);
  if (((sVar1 != 0x54a) && (sVar1 != 0x5ae)) &&
     ((sVar1 != 0x108 &&
      ((*(char *)(iVar6 + 0x146) != '\0' && ((*(ushort *)(iVar6 + 0x100) & 8) == 0)))))) {
    FUN_800e8630(param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017691c
 * EN v1.0 Address: 0x8017691C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80176E60
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017691c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80176920
 * EN v1.0 Address: 0x80176920
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x80177470
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80176920(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  if (((*(char *)(*(int *)(param_9 + 0x4c) + 0x1d) != '\x02') &&
      (*(char *)(param_11 + 0x80) == '\x01')) &&
     (iVar1 = (int)*(char *)(*(int *)(param_9 + 0x4c) + 0x1a), -1 < iVar1)) {
    FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,'\x01',
                 param_11,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_11 + 0x80) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801769e8
 * EN v1.0 Address: 0x801769E8
 * EN v1.0 Size: 2076b
 * EN v1.1 Address: 0x8017750C
 * EN v1.1 Size: 1632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801769e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short *psVar6;
  uint uVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  iVar10 = *(int *)(param_9 + 0x4c);
  psVar9 = *(short **)(param_9 + 0xb8);
  psVar6 = (short *)FUN_80017a98();
  if (psVar6 != (short *)0x0) {
    *psVar9 = *psVar9 - (ushort)DAT_803dc070;
    if (*psVar9 < 0) {
      *psVar9 = 0;
    }
    if ((((*(char *)(iVar10 + 0x1f) != '\0') && (*(char *)((int)psVar9 + 0xd) == '\0')) &&
        (-1 < DAT_803ddb38)) && ((int)DAT_803ddb38 == (int)*(char *)(iVar10 + 0x19))) {
      param_12 = FUN_80056600();
      param_11 = 0;
      param_13 = *DAT_803dd72c;
      (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6);
      *(undefined *)((int)psVar9 + 0xd) = 1;
    }
    cVar2 = *(char *)(iVar10 + 0x1d);
    if (cVar2 == '\x02') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)lbl_803E4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      uVar7 = FUN_80017690((int)psVar9[1]);
      if (((uVar7 == 0) || (*(char *)(psVar9 + 6) != '\0')) ||
         ((*(char *)(iVar10 + 0x1c) == '\0' ||
          (((double)*(float *)(psVar9 + 4) < dVar11 ||
           (*(int *)(psVar6 + 0x18) != *(int *)(param_9 + 0x30))))))) {
        if ((*(char *)(psVar9 + 6) == '\x01') &&
           ((((uVar7 = FUN_80017690((int)psVar9[1]), uVar7 != 0 && (*psVar9 == 0)) &&
             (dVar11 <= (double)*(float *)(psVar9 + 4))) && (-1 < *(char *)(iVar10 + 0x1a))))) {
          uVar12 = FUN_80017698((int)psVar9[1],0);
          FUN_80053c98(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\0',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar9[2],param_9,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
    else if (cVar2 < '\x02') {
      if (cVar2 == '\0') {
        if ((-1 < DAT_803ddb38) || (uVar7 = FUN_80017690(0xd53), uVar7 != 0)) {
          param_2 = (double)(*(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc));
          param_3 = (double)(*(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10));
          fVar3 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
          dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                        (float)(param_2 * param_2 +
                                               (double)(float)(param_3 * param_3))));
          if ((*(char *)(psVar9 + 6) == '\0') &&
             (((*(char *)(iVar10 + 0x1c) != '\0' && (dVar11 < (double)*(float *)(psVar9 + 4))) &&
              (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
            if (*(short *)(param_9 + 0x46) == 0x27e) {
              FUN_80017698(0xd53,1);
              iVar8 = FUN_80056600();
              param_13 = *DAT_803dd72c;
              (**(code **)(param_13 + 0x1c))(psVar6 + 6,(int)*psVar6,0,iVar8);
            }
            param_11 = 0xffffffff;
            param_12 = *DAT_803dd6d4;
            (**(code **)(param_12 + 0x48))((int)psVar9[2],param_9);
            FUN_80017698(0xd53,0);
            DAT_803dda60 = 2;
            *(undefined *)(psVar9 + 6) = 1;
          }
        }
        if ((-1 < *(char *)(iVar10 + 0x1a)) &&
           (dVar11 = (double)FUN_8001771c((float *)(param_9 + 0x18),(float *)(psVar6 + 0xc)),
           dVar11 < (double)*(float *)(psVar9 + 4))) {
          FUN_80053c98(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                       param_15,param_16);
        }
      }
      else if (-1 < cVar2) {
        fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
        fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
        fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
        dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
        if (((-1 < DAT_803ddb38) && (*(char *)(iVar10 + 0x1c) != '\0')) &&
           ((dVar11 < (double)lbl_803E4270 &&
            (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
          DAT_803dda60 = 2;
        }
        if ((((*psVar9 == 0) &&
             (dVar11 < (double)(float)((double)CONCAT44(0x43300000,
                                                        (int)*(char *)(iVar10 + 0x1e) ^ 0x80000000)
                                      - DOUBLE_803e4278))) &&
            (bVar1 = -1 < *(char *)(iVar10 + 0x1a), bVar1)) && (bVar1)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        }
      }
    }
    else if (cVar2 == '\x04') {
      dVar11 = (double)*(float *)(psVar9 + 4);
      if ((double)lbl_803E4274 != dVar11) {
        param_2 = (double)(*(float *)(psVar6 + 0xc) - *(float *)(param_9 + 0x18));
        param_3 = (double)(*(float *)(psVar6 + 0xe) - *(float *)(param_9 + 0x1c));
        fVar3 = *(float *)(psVar6 + 0x10) - *(float *)(param_9 + 0x20);
        dVar11 = FUN_80293900((double)(fVar3 * fVar3 +
                                      (float)(param_2 * param_2 + (double)(float)(param_3 * param_3)
                                             )));
      }
      if (((-1 < DAT_803ddb38) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        param_11 = 0xffffffff;
        param_12 = *DAT_803dd6d4;
        (**(code **)(param_12 + 0x48))((int)psVar9[2],param_9);
        DAT_803dda60 = 2;
        *(undefined *)(psVar9 + 6) = 1;
      }
      uVar7 = FUN_80017690((int)psVar9[1]);
      if ((((uVar7 != 0) && (*psVar9 == 0)) && (dVar11 <= (double)*(float *)(psVar9 + 4))) &&
         (-1 < *(char *)(iVar10 + 0x1a))) {
        uVar12 = FUN_80017698((int)psVar9[1],0);
        FUN_80053c98(uVar12,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(char *)(iVar10 + 0x1a),'\x01',param_11,param_12,param_13,param_14,
                     param_15,param_16);
      }
    }
    else if (cVar2 < '\x04') {
      fVar3 = *(float *)(psVar6 + 6) - *(float *)(param_9 + 0xc);
      fVar4 = *(float *)(psVar6 + 8) - *(float *)(param_9 + 0x10);
      fVar5 = *(float *)(psVar6 + 10) - *(float *)(param_9 + 0x14);
      dVar11 = FUN_80293900((double)(fVar5 * fVar5 + fVar3 * fVar3 + fVar4 * fVar4));
      uVar7 = FUN_80017690((int)psVar9[1]);
      if (((uVar7 != 0) && (*(char *)(psVar9 + 6) == '\0')) &&
         ((*(char *)(iVar10 + 0x1c) != '\0' &&
          ((dVar11 < (double)*(float *)(psVar9 + 4) &&
           (*(int *)(psVar6 + 0x18) == *(int *)(param_9 + 0x30))))))) {
        FUN_80017698((int)psVar9[1],0);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar9[2],param_9,0xffffffff);
        *(undefined *)(psVar9 + 6) = 1;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177204
 * EN v1.0 Address: 0x80177204
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80177B6C
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177204(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80177208
 * EN v1.0 Address: 0x80177208
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80177C58
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177208(int param_1)
{
  if (*(char *)(*(int *)(param_1 + 0xb8) + 8) == '\x04') {
    (**(code **)(*DAT_803dd6f8 + 0x18))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017724c
 * EN v1.0 Address: 0x8017724C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80177C9C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017724c(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017726c
 * EN v1.0 Address: 0x8017726C
 * EN v1.0 Size: 1156b
 * EN v1.1 Address: 0x80177CC4
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017726c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 extraout_f1;
  undefined8 uVar11;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58 [2];
  undefined4 local_50;
  uint uStack_4c;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  iVar4 = FUN_80286840();
  pfVar7 = *(float **)(iVar4 + 0xb8);
  *(undefined4 *)(iVar4 + 0x80) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(iVar4 + 0x84) = *(undefined4 *)(iVar4 + 0x10);
  *(undefined4 *)(iVar4 + 0x88) = *(undefined4 *)(iVar4 + 0x14);
  switch(*(undefined *)(pfVar7 + 2)) {
  case 0:
    iVar10 = FUN_80017a98();
    dVar12 = DOUBLE_803e4290;
    while (iVar10 != 0) {
      fVar2 = *(float *)(iVar4 + 0xc) - *(float *)(iVar10 + 0xc);
      fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar10 + 0x10);
      fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(iVar10 + 0x14);
      dVar13 = FUN_80293900((double)(fVar3 * fVar3 + fVar2 * fVar2 + fVar1 * fVar1));
      uStack_4c = *(uint *)(iVar4 + 0xf8) ^ 0x80000000;
      local_50 = 0x43300000;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar12)) {
        iVar6 = *(int *)(iVar10 + 0x54);
        *(char *)(iVar6 + 0x71) = *(char *)(iVar6 + 0x71) + '\x01';
        *(ushort *)(iVar6 + 0x60) = *(ushort *)(iVar6 + 0x60) & 0xfffe;
        *(char *)(*(int *)(iVar4 + 0x54) + 0x71) = *(char *)(*(int *)(iVar4 + 0x54) + 0x71) + '\x01'
        ;
      }
      if (*(short *)(iVar10 + 0x44) == 1) {
        iVar10 = FUN_80017a90();
      }
      else {
        iVar10 = 0;
      }
    }
    break;
  case 1:
    ObjList_ContainsObject(*(int *)(iVar4 + 0xf4));
    break;
  case 3:
    iVar10 = FUN_80017a98();
    if (iVar10 != 0) {
      DAT_803ad3e0 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ad3e4 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ad3e8 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 4:
    *(uint *)(iVar4 + 0xf8) = *(int *)(iVar4 + 0xf8) - (uint)DAT_803dc070;
    if (*(int *)(*(int *)(iVar4 + 0x54) + 0x50) != 0) {
      *(undefined2 *)(*(int *)(iVar4 + 0x54) + 0x60) = 0;
    }
    iVar10 = *(int *)(iVar4 + 0xf4);
    if (iVar10 != 0) {
      iVar6 = ObjList_ContainsObject(iVar10);
      fVar2 = lbl_803E4284;
      if (iVar6 == 0) break;
      fVar1 = *(float *)(iVar10 + 0x14);
      *(float *)(iVar4 + 0xc) =
           ((*(float *)(iVar10 + 0xc) - *(float *)(iVar4 + 0xc)) / lbl_803E4284) * lbl_803DC074
           + *(float *)(iVar4 + 0xc);
      *(float *)(iVar4 + 0x14) =
           ((fVar1 - *(float *)(iVar4 + 0x14)) / fVar2) * lbl_803DC074 + *(float *)(iVar4 + 0x14);
      fVar2 = *(float *)(iVar10 + 0xc) - *pfVar7;
      fVar1 = *(float *)(iVar10 + 0x14) - pfVar7[1];
      dVar12 = FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      dVar13 = (double)(float)((double)lbl_803E4288 + dVar12);
      dVar15 = (double)(*(float *)(iVar4 + 0xc) - *pfVar7);
      dVar14 = (double)(*(float *)(iVar4 + 0x14) - pfVar7[1]);
      dVar12 = FUN_80293900((double)(float)(dVar15 * dVar15 + (double)(float)(dVar14 * dVar14)));
      if (dVar13 < dVar12) {
        *(float *)(iVar4 + 0xc) = *pfVar7 + (float)(dVar15 * (double)(float)(dVar13 / dVar12));
        *(float *)(iVar4 + 0x14) = pfVar7[1] + (float)(dVar14 * (double)(float)(dVar13 / dVar12));
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar4,0x25,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(iVar4,0x56,0,0,0xffffffff,0);
    }
    cVar5 = FUN_800632f4((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x10),
                         (double)*(float *)(iVar4 + 0x14),iVar4,local_58,0,0);
    fVar2 = lbl_803E428C;
    for (iVar10 = 0; iVar10 < cVar5; iVar10 = iVar10 + 1) {
      fVar1 = **(float **)(local_58[0] + iVar10 * 4);
      if ((fVar1 < fVar2 + *(float *)(iVar4 + 0x10)) && (*(float *)(iVar4 + 0x10) - fVar2 < fVar1))
      {
        *(float *)(iVar4 + 0x10) = fVar1;
        iVar10 = (int)cVar5;
      }
    }
    break;
  case 5:
    iVar10 = FUN_80017a98();
    iVar6 = FUN_80294c54(iVar10);
    if ((iVar10 != 0) && (iVar6 != 0)) {
      DAT_803ad3e0 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ad3e4 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ad3e8 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 7:
    iVar9 = *(int *)(iVar4 + 0x54);
    iVar8 = *(int *)(*(int *)(iVar4 + 0xf4) + 0x54);
    iVar10 = iVar8;
    uVar11 = extraout_f1;
    for (iVar6 = 0; iVar6 < *(char *)(iVar8 + 0x71); iVar6 = iVar6 + 1) {
      if (*(int *)(iVar10 + 0x7c) == iVar4) {
        *(ushort *)(iVar9 + 0x60) = *(ushort *)(iVar9 + 0x60) & 0xfffe;
        uVar11 = FUN_80017ac8(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      iVar10 = iVar10 + 4;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801776f0
 * EN v1.0 Address: 0x801776F0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801782E8
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801776f0(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177710
 * EN v1.0 Address: 0x80177710
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x80178310
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177710(ushort *param_1)
{
  int iVar1;
  undefined uVar2;
  float *pfVar3;
  ushort *puVar4;
  ushort local_28;
  ushort local_26;
  ushort local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = FUN_80017a98();
  pfVar3 = *(float **)(param_1 + 0x5c);
  if ((iVar1 != 0) && (puVar4 = *(ushort **)(iVar1 + 200), puVar4 != (ushort *)0x0)) {
    param_1[2] = puVar4[2];
    param_1[1] = puVar4[1];
    *param_1 = *puVar4;
    if (*(char *)(*(int *)(param_1 + 0x26) + 0x19) == '\0') {
      uVar2 = 1;
    }
    else {
      uVar2 = 3;
    }
    ObjHits_SetHitVolumeSlot((int)param_1,0x10,uVar2,0);
    *pfVar3 = *pfVar3 - lbl_803DC074;
    local_1c = lbl_803E429C;
    if (*pfVar3 <= lbl_803E429C) {
      *pfVar3 = *pfVar3 + lbl_803E42A0;
      *(float *)(param_1 + 0x12) = local_1c;
      *(float *)(param_1 + 0x16) = local_1c;
      *(float *)(param_1 + 0x14) = lbl_803E42A4;
      local_18 = local_1c;
      local_14 = local_1c;
      local_20 = lbl_803E4298;
      local_24 = puVar4[2];
      local_26 = puVar4[1];
      local_28 = *puVar4;
      FUN_80017748(&local_28,(float *)(param_1 + 0x12));
      ObjPath_GetPointWorldPosition(puVar4,0,(float *)(param_1 + 6),(undefined4 *)(param_1 + 8),
                   (float *)(param_1 + 10),0);
      ObjHits_EnableObject((int)param_1);
    }
    *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * lbl_803DC074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * lbl_803DC074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * lbl_803DC074 + *(float *)(param_1 + 10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80177874
 * EN v1.0 Address: 0x80177874
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801784A4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80177874(int param_1,int param_2)
{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
              DOUBLE_803e42a8);
  ObjHits_SetTargetMask(param_1,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801778d0
 * EN v1.0 Address: 0x801778D0
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801784F8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801778d0(int param_1)
{
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0x10) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801778e0
 * EN v1.0 Address: 0x801778E0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x80178508
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801778e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10)
{
  float fVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  float *pfVar5;
  ushort local_28;
  short local_26;
  short local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  psVar2 = (short *)FUN_80017a90();
  local_1c = lbl_803E42B0;
  if ((*(char *)(param_10 + 0x10) == '\0') && (psVar2 != (short *)0x0)) {
    *(float *)(param_9 + 0x24) = lbl_803E42B0;
    *(float *)(param_9 + 0x28) = local_1c;
    *(float *)(param_9 + 0x2c) = lbl_803E42B4;
    local_18 = local_1c;
    local_14 = local_1c;
    local_20 = lbl_803E42B8;
    local_24 = psVar2[2];
    local_26 = psVar2[1];
    iVar4 = FUN_801365ac((int)psVar2);
    local_28 = *psVar2 + (short)iVar4;
    FUN_80017748(&local_28,(float *)(param_9 + 0x24));
    if ((psVar2[0x58] & 0x800U) == 0) {
      pfVar5 = (float *)(psVar2 + 6);
    }
    else {
      pfVar5 = (float *)FUN_801365b8((int)psVar2);
    }
    fVar1 = lbl_803E42BC;
    *(float *)(param_10 + 4) = -(lbl_803E42BC * *(float *)(param_9 + 0x24) - *pfVar5);
    *(float *)(param_10 + 8) = -(fVar1 * *(float *)(param_9 + 0x28) - pfVar5[1]);
    *(float *)(param_10 + 0xc) = -(fVar1 * *(float *)(param_9 + 0x2c) - pfVar5[2]);
    if (*(char *)(param_10 + 0x11) == '\0') {
      ObjHits_ClearHitVolumes(param_9);
    }
    else {
      *(char *)(param_10 + 0x11) = *(char *)(param_10 + 0x11) + -1;
    }
    uVar3 = 1;
  }
  else {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    uVar3 = 0;
  }
  return uVar3;
}


/* Trivial 4b 0-arg blr leaves. */
void invhit_hitDetect(void) {}
void invhit_release(void) {}
void invhit_initialise(void) {}
void iceblast_free(void) {}
void iceblast_hitDetect(void) {}
void iceblast_release(void) {}
void iceblast_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int pushable_getExtraSize(void) { return 0x148; }
int pushable_func08(void) { return 0x48; }
int WarpPoint_getExtraSize(void) { return 0x10; }
int WarpPoint_func08(void) { return 0x1; }
int invhit_getExtraSize(void) { return 0xc; }
int invhit_func08(void) { return 0x0; }
int iceblast_getExtraSize(void) { return 0x4; }
int iceblast_func08(void) { return 0x0; }
int flameblast_getExtraSize(void) { return 0x14; }

/* 16b chained patterns. */
#pragma scheduling off
#pragma peephole off
void objSetAnimSpeedTo1(int *obj) { u8 v = 0x1; *((u8*)((int**)obj)[0xb8/4] + 0x10) = v; }
#pragma peephole reset
#pragma scheduling reset

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E35E8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3600;
#pragma scheduling off
#pragma peephole off
void invhit_render(void) { objRenderFn_8003b8f4(lbl_803E35E8); }
void iceblast_render(void) { objRenderFn_8003b8f4(lbl_803E3600); }
#pragma peephole reset
#pragma scheduling reset
