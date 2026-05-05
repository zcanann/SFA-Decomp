#include "ghidra_import.h"
#include "main/dll/CF/windlift.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_800068c0();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjHits_MarkObjectPositionDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern int FUN_800575b4();
extern uint FUN_800620e8();
extern int FUN_800632f4();
extern uint FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8013651c();
extern int FUN_80184600();
extern undefined4 FUN_801847e8();
extern undefined4 FUN_80247eb8();
extern int FUN_80286838();
extern undefined4 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern uint FUN_80294cc4();
extern undefined4 FUN_80294d28();
extern undefined4 FUN_80294d68();
extern int FUN_80294d6c();

extern undefined4 DAT_802c2a18;
extern undefined4 DAT_802c2a1c;
extern undefined4 DAT_802c2a20;
extern undefined4 DAT_802c2a24;
extern undefined4 DAT_802c2a28;
extern undefined4 DAT_802c2a2c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca18;
extern undefined4 DAT_803dca1c;
extern undefined4 DAT_803dca20;
extern char DAT_803dca24;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803de750;
extern undefined4* DAT_803de754;
extern undefined4 DAT_803e4688;
extern f64 DOUBLE_803e46e0;
extern f64 DOUBLE_803e46e8;
extern f64 DOUBLE_803e4710;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dca2c;
extern f32 FLOAT_803dca30;
extern f32 FLOAT_803dca34;
extern f32 FLOAT_803dca38;
extern f32 FLOAT_803e468c;
extern f32 FLOAT_803e4690;
extern f32 FLOAT_803e4694;
extern f32 FLOAT_803e4698;
extern f32 FLOAT_803e469c;
extern f32 FLOAT_803e46a0;
extern f32 FLOAT_803e46a4;
extern f32 FLOAT_803e46a8;
extern f32 FLOAT_803e46ac;
extern f32 FLOAT_803e46b0;
extern f32 FLOAT_803e46b4;
extern f32 FLOAT_803e46b8;
extern f32 FLOAT_803e46bc;
extern f32 FLOAT_803e46c0;
extern f32 FLOAT_803e46c4;
extern f32 FLOAT_803e46c8;
extern f32 FLOAT_803e46cc;
extern f32 FLOAT_803e46d0;
extern f32 FLOAT_803e46d4;
extern f32 FLOAT_803e46d8;
extern f32 FLOAT_803e46f0;
extern f32 FLOAT_803e46f4;
extern f32 FLOAT_803e46f8;
extern f32 FLOAT_803e46fc;
extern f32 FLOAT_803e4700;
extern f32 FLOAT_803e4704;
extern f32 FLOAT_803e4708;
extern f32 FLOAT_803e470c;
extern f32 FLOAT_803e4718;
extern f32 FLOAT_803e471c;

/*
 * --INFO--
 *
 * Function: scarab_update
 * EN v1.0 Address: 0x80184930
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80184D4C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void scarab_update(void)
{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  char in_r8;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_80286838();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_80017a54(iVar1);
  if (*(short *)(iVar1 + 0x46) == 0x3d6) {
    iVar4 = 0;
    pcVar3 = &DAT_803dca24;
    iVar6 = 7;
    do {
      if (*pcVar3 == *(char *)(*(int *)(iVar2 + 0x34) + 8)) {
        iVar4 = iVar4 + 1;
        if (iVar4 == 7) {
          iVar4 = 0;
        }
        *(undefined *)(*(int *)(iVar2 + 0x34) + 8) = (&DAT_803dca24)[iVar4];
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  if (*(short *)(iVar5 + 0x10) == 0) {
    if (*(int *)(iVar1 + 0xf8) == 0) {
      if (in_r8 == '\0') goto LAB_80184e70;
    }
    else if (in_r8 != -1) goto LAB_80184e70;
    FUN_8003b818(iVar1);
    if ((in_r8 != '\0') && (*(char *)(iVar1 + 0x36) != '\0')) {
      FUN_800810f4((double)FLOAT_803e4698,(double)FLOAT_803e469c,iVar1,5,
                   (int)*(short *)(iVar5 + 0x22) & 0xff,1,0x14,0,0);
    }
  }
LAB_80184e70:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80184a54
 * EN v1.0 Address: 0x80184A54
 * EN v1.0 Size: 3668b
 * EN v1.1 Address: 0x80184E88
 * EN v1.1 Size: 3476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80184a54(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  float fVar2;
  short sVar3;
  ushort uVar4;
  bool bVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  ushort *puVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  undefined4 *puVar14;
  int iVar15;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar16;
  int iVar17;
  double dVar18;
  undefined8 uVar19;
  double dVar20;
  double dVar21;
  double in_f31;
  double in_ps31_1;
  undefined4 local_170;
  undefined4 local_16c;
  undefined4 local_168;
  float local_164;
  uint local_160;
  undefined4 *local_15c;
  float local_158 [3];
  float local_14c;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  uint auStack_134 [6];
  ushort local_11c [4];
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  int aiStack_104 [21];
  float afStack_b0 [16];
  float local_70 [4];
  undefined local_60;
  undefined local_5c;
  undefined8 local_40;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar10 = (ushort *)FUN_8028683c();
  iVar17 = 0;
  local_15c = (undefined4 *)0x0;
  local_140 = DAT_802c2a18;
  local_13c = DAT_802c2a1c;
  local_138 = DAT_802c2a20;
  local_14c = DAT_802c2a24;
  local_148 = DAT_802c2a28;
  local_144 = DAT_802c2a2c;
  bVar5 = false;
  pfVar16 = *(float **)(puVar10 + 0x5c);
  iVar11 = FUN_80017a98();
  if ((*(byte *)(pfVar16 + 10) & 1) != 0) {
    while (iVar12 = ObjMsg_Pop((int)puVar10,&local_160,(uint *)0x0,(uint *)0x0), iVar12 != 0) {
      if (local_160 == 0x7000b) {
        local_168 = DAT_803e4688;
        FUN_80294d28(iVar11,(uint)*(byte *)((int)&local_168 + (uint)*(byte *)((int)pfVar16 + 0x27)))
        ;
        *(undefined2 *)(pfVar16 + 4) = 0x50;
        *(undefined2 *)(pfVar16 + 5) = 0;
        *(byte *)(pfVar16 + 10) = *(byte *)(pfVar16 + 10) & 0xfe;
      }
    }
    if ((*(byte *)(pfVar16 + 10) & 1) != 0) goto LAB_80185bfc;
  }
  uVar19 = FUN_800068c0((uint)puVar10,0x406,3);
  fVar2 = FLOAT_803e46b8;
  sVar3 = *(short *)(pfVar16 + 5);
  if (sVar3 == 0) {
    *(ushort *)(pfVar16 + 4) = *(short *)(pfVar16 + 4) - (ushort)DAT_803dc070;
    if (*(short *)(pfVar16 + 4) < 1) {
      *(undefined2 *)(pfVar16 + 4) = 0;
      FUN_80017ac8(uVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar10);
    }
  }
  else {
    cVar1 = *(char *)(pfVar16 + 9);
    if (cVar1 == '\0') {
      if (*(int *)(puVar10 + 0x2a) != 0) {
        ObjHits_EnableObject((int)puVar10);
      }
      *(float *)(puVar10 + 6) =
           *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
      *(float *)(puVar10 + 8) =
           *(float *)(puVar10 + 0x14) * FLOAT_803dc074 + *(float *)(puVar10 + 8);
      *(float *)(puVar10 + 10) =
           *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
      if (FLOAT_803e46a0 < *(float *)(puVar10 + 0x14)) {
        *(float *)(puVar10 + 0x14) = FLOAT_803e46a4 * FLOAT_803dc074 + *(float *)(puVar10 + 0x14);
      }
      puVar10[2] = puVar10[2] + *(short *)((int)pfVar16 + 0x16) * (ushort)DAT_803dc070;
      iVar17 = FUN_80184600();
      uVar13 = (uint)(iVar17 != 0);
      if (uVar13 == 0) {
        uVar13 = FUN_800620e8(puVar10 + 0x40,puVar10 + 6,(float *)0x0,aiStack_104,(int *)puVar10,8,
                              0xffffffff,0,0);
      }
      if (uVar13 != 0) {
        puVar10[2] = 0;
        *(undefined *)(pfVar16 + 9) = 1;
        *(ushort *)(pfVar16 + 6) = *puVar10;
        fVar9 = FLOAT_803e46b4;
        fVar8 = FLOAT_803e46b0;
        fVar7 = FLOAT_803e46ac;
        fVar6 = FLOAT_803e46a8;
        fVar2 = FLOAT_803e4690;
        uVar4 = puVar10[0x23];
        if (uVar4 == 0x3d3) {
          *pfVar16 = FLOAT_803e46a8 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar6 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d4) {
          *pfVar16 = FLOAT_803e46ac * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar7 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d5) {
          *pfVar16 = FLOAT_803e46b0 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar8 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3d6) {
          *pfVar16 = FLOAT_803e46b4 * *(float *)(puVar10 + 0x12);
          pfVar16[1] = fVar9 * *(float *)(puVar10 + 0x16);
        }
        else if (uVar4 == 0x3df) {
          *pfVar16 = FLOAT_803e4690;
          pfVar16[1] = fVar2;
        }
      }
    }
    else if ((cVar1 == '\x02') && (sVar3 != 0)) {
      local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar16 + 7) ^ 0x80000000);
      if (pfVar16[2] < (float)(local_40 - DOUBLE_803e46e0)) {
        pfVar16[2] = FLOAT_803e46b8 * FLOAT_803dc074 + pfVar16[2];
        local_140 = *(float *)(puVar10 + 6);
        local_14c = fVar2 * *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + local_140;
        local_13c = *(float *)(puVar10 + 8);
        local_148 = fVar2 * FLOAT_803dc074 + local_13c;
        local_138 = *(float *)(puVar10 + 10);
        local_144 = fVar2 * *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + local_138;
        local_70[0] = FLOAT_803e4690;
        local_60 = 0xff;
        local_5c = 0;
        trackDolphin_buildSweptBounds(auStack_134,&local_140,&local_14c,local_70,1);
        FUN_80063a74(puVar10,auStack_134,0,'\x01');
        iVar17 = FUN_80063a68();
        *(float *)(puVar10 + 6) = local_14c;
        *(float *)(puVar10 + 8) = local_148;
        *(float *)(puVar10 + 10) = local_144;
        if (iVar17 != 0) {
          FUN_801847e8(puVar10,0,'\0',afStack_b0);
        }
      }
      iVar17 = ObjHits_GetPriorityHit((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar17 == 0xe) {
        *(undefined2 *)((int)pfVar16 + 0x1a) = 0xfa;
        FUN_80006824((uint)puVar10,0x40);
        *(float *)(puVar10 + 0x12) = *(float *)(iVar11 + 0xc) - *(float *)(puVar10 + 6);
        *(float *)(puVar10 + 0x16) = *(float *)(iVar11 + 0x14) - *(float *)(puVar10 + 10);
        *puVar10 = 0;
        dVar20 = (double)(*(float *)(puVar10 + 0x12) * *(float *)(puVar10 + 0x12) +
                         *(float *)(puVar10 + 0x16) * *(float *)(puVar10 + 0x16));
        if (dVar20 != (double)FLOAT_803e4690) {
          dVar20 = FUN_80293900(dVar20);
        }
        dVar18 = (double)FLOAT_803e4694;
        *(float *)(puVar10 + 0x12) = *(float *)(puVar10 + 0x12) / (float)(dVar18 * dVar20);
        *(float *)(puVar10 + 0x16) = *(float *)(puVar10 + 0x16) / (float)(dVar18 * dVar20);
        puVar10[1] = 0;
        *(float *)(puVar10 + 0x14) = FLOAT_803e46bc;
        local_110 = FLOAT_803e4690;
        local_10c = FLOAT_803e4690;
        local_108 = FLOAT_803e4690;
        local_114 = FLOAT_803e4698;
        local_11c[2] = 0;
        local_11c[1] = 0;
        uVar13 = FUN_80017760(0xffffd8f0,10000);
        local_11c[0] = (ushort)uVar13;
        FUN_80017748(local_11c,(float *)(puVar10 + 0x12));
        uVar13 = FUN_80017730();
        iVar17 = (int)(short)*puVar10 - (uVar13 & 0xffff);
        if (0x8000 < iVar17) {
          iVar17 = iVar17 + -0xffff;
        }
        if (iVar17 < -0x8000) {
          iVar17 = iVar17 + 0xffff;
        }
        *puVar10 = (ushort)iVar17;
        *(undefined *)(pfVar16 + 9) = 0;
        pfVar16[2] = FLOAT_803e4690;
        fVar2 = FLOAT_803e468c;
        *(float *)(puVar10 + 6) =
             FLOAT_803e468c * *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
        *(float *)(puVar10 + 8) =
             fVar2 * *(float *)(puVar10 + 0x14) * FLOAT_803dc074 + *(float *)(puVar10 + 8);
        *(float *)(puVar10 + 10) =
             fVar2 * *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
      }
    }
    else if ((cVar1 == '\x01') && (sVar3 != 0)) {
      if (*(short *)((int)pfVar16 + 0x1a) == 0) {
        iVar17 = 0;
        dVar20 = (double)FLOAT_803e46c0;
        iVar12 = FUN_800632f4((double)*(float *)(puVar10 + 6),(double)*(float *)(puVar10 + 8),
                              (double)*(float *)(puVar10 + 10),puVar10,&local_15c,1,0);
        iVar15 = 0;
        dVar21 = (double)FLOAT_803dca30;
        puVar14 = local_15c;
        if (0 < iVar12) {
          do {
            dVar18 = (double)(*(float *)*puVar14 - *(float *)(puVar10 + 8));
            if (dVar18 <= dVar21) {
              if (dVar18 < (double)FLOAT_803e4690) {
                dVar18 = -dVar18;
              }
              if (dVar18 < dVar20) {
                iVar17 = iVar15;
                dVar20 = dVar18;
              }
            }
            puVar14 = puVar14 + 1;
            iVar15 = iVar15 + 1;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
        if (local_15c == (undefined4 *)0x0) {
          *(float *)(puVar10 + 8) = pfVar16[3];
        }
        else {
          *(undefined4 *)(puVar10 + 8) = *(undefined4 *)local_15c[iVar17];
          fVar2 = *(float *)(local_15c[iVar17] + 8);
          if (fVar2 < FLOAT_803e4690) {
            fVar2 = -fVar2;
          }
          if (FLOAT_803dca2c <= fVar2) {
            FUN_801847e8(puVar10,local_15c[iVar17],'\x01',afStack_b0);
          }
          else {
            bVar5 = true;
          }
        }
        if (puVar10[0x23] != 0x3d6) {
          uVar13 = FUN_80017760(0xfffffa4c,0x5b4);
          *puVar10 = *puVar10 + (short)uVar13;
        }
        *(float *)(puVar10 + 0x12) = *pfVar16;
        local_110 = FLOAT_803e4690;
        *(float *)(puVar10 + 0x14) = FLOAT_803e4690;
        *(float *)(puVar10 + 0x16) = pfVar16[1];
        local_10c = local_110;
        local_108 = local_110;
        local_114 = FLOAT_803e4698;
        local_11c[2] = 0;
        local_11c[1] = 0;
        local_11c[0] = *puVar10 - *(short *)(pfVar16 + 6);
        FUN_80017748(local_11c,(float *)(puVar10 + 0x12));
        *(ushort *)(pfVar16 + 5) = *(short *)(pfVar16 + 5) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar16 + 5) < 1) {
          iVar12 = FUN_800575b4((double)(*(float *)(puVar10 + 0x54) * *(float *)(puVar10 + 4)),
                                (float *)(puVar10 + 6));
          if (iVar12 == 0) {
            *(undefined2 *)(pfVar16 + 5) = 0;
          }
          else {
            *(undefined2 *)(pfVar16 + 5) = 1;
          }
        }
        if (bVar5) {
          uVar13 = FUN_80017730();
          local_40 = (double)CONCAT44(0x43300000,uVar13 & 0xffff);
          iVar12 = (int)(FLOAT_803dca34 * (float)(local_40 - DOUBLE_803e46e8) + FLOAT_803e46c4);
          local_38 = (double)(longlong)iVar12;
          *puVar10 = (ushort)iVar12;
          dVar21 = (double)FLOAT_803e468c;
          *(float *)(puVar10 + 6) =
               FLOAT_803dc074 * (float)(dVar21 * (double)*(float *)(local_15c[iVar17] + 4)) +
               *(float *)(puVar10 + 6);
          dVar18 = (double)FLOAT_803dc074;
          *(float *)(puVar10 + 10) =
               (float)(dVar18 * (double)(float)(dVar21 * (double)*(float *)(local_15c[iVar17] + 0xc)
                                               ) + (double)*(float *)(puVar10 + 10));
          *(undefined4 *)(puVar10 + 0x12) = *(undefined4 *)(local_15c[iVar17] + 4);
          *(undefined4 *)(puVar10 + 0x16) = *(undefined4 *)(local_15c[iVar17] + 0xc);
        }
        else {
          *(float *)(puVar10 + 6) =
               *(float *)(puVar10 + 0x12) * FLOAT_803dc074 + *(float *)(puVar10 + 6);
          *(float *)(puVar10 + 10) =
               *(float *)(puVar10 + 0x16) * FLOAT_803dc074 + *(float *)(puVar10 + 10);
          dVar20 = FUN_80293900((double)(*(float *)(puVar10 + 0x12) * *(float *)(puVar10 + 0x12) +
                                        *(float *)(puVar10 + 0x16) * *(float *)(puVar10 + 0x16)));
          FUN_8002f6ac(dVar20,(int)puVar10,&local_164);
          dVar18 = (double)FLOAT_803dc074;
          FUN_8002fc3c((double)local_164,dVar18);
        }
        in_r9 = 0xffffffff;
        in_r10 = 0;
        iVar17 = FUN_800620e8(puVar10 + 0x40,puVar10 + 6,(float *)0x0,aiStack_104,(int *)puVar10,8,
                              0xffffffff,0,0);
        local_70[0] = FLOAT_803e4698;
        local_60 = 0xff;
        local_5c = 10;
        trackDolphin_buildSweptBounds(auStack_134,(float *)(puVar10 + 0x40),(float *)(puVar10 + 6),
                                      local_70,1);
        FUN_80063a74(puVar10,auStack_134,0,'\x01');
        in_r7 = afStack_b0;
        in_r8 = 0;
        uVar13 = FUN_80063a68();
        if (((iVar17 != 0) ||
            (dVar20 = (double)FUN_8001771c((float *)(puVar10 + 0xc),
                                           (float *)(*(int *)(puVar10 + 0x26) + 8)),
            (double)FLOAT_803e46c8 < dVar20)) || (((uVar13 & 1) != 0 && ((uVar13 & 0x10) == 0)))) {
          FUN_80247eb8((float *)(*(int *)(puVar10 + 0x26) + 8),(float *)(puVar10 + 6),local_158);
          uVar13 = FUN_80017730();
          local_38 = (double)CONCAT44(0x43300000,uVar13 & 0xffff);
          dVar18 = (double)(float)(local_38 - DOUBLE_803e46e8);
          iVar17 = (int)((double)FLOAT_803dca38 * dVar18 + (double)FLOAT_803e46c4);
          local_40 = (double)(longlong)iVar17;
          *puVar10 = (ushort)iVar17;
        }
      }
      else {
        dVar20 = (double)FLOAT_803e46c0;
        dVar18 = (double)*(float *)(puVar10 + 8);
        dVar21 = (double)*(float *)(puVar10 + 10);
        iVar12 = FUN_800632f4((double)*(float *)(puVar10 + 6),dVar18,dVar21,puVar10,&local_15c,1,0);
        iVar15 = 0;
        puVar14 = local_15c;
        if (0 < iVar12) {
          do {
            dVar21 = (double)*(float *)*puVar14;
            dVar18 = (double)(float)(dVar21 - (double)*(float *)(puVar10 + 8));
            if (dVar18 < (double)FLOAT_803e4690) {
              dVar18 = (double)(float)(dVar18 * (double)FLOAT_803e46cc);
            }
            if (dVar18 < dVar20) {
              iVar17 = iVar15;
              dVar20 = dVar18;
            }
            puVar14 = puVar14 + 1;
            iVar15 = iVar15 + 1;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
        if (local_15c == (undefined4 *)0x0) {
          *(float *)(puVar10 + 8) = pfVar16[3];
        }
        else {
          *(undefined4 *)(puVar10 + 8) = *(undefined4 *)local_15c[iVar17];
          FUN_801847e8(puVar10,local_15c[iVar17],'\x01',afStack_b0);
        }
        *(ushort *)((int)pfVar16 + 0x1a) = *(short *)((int)pfVar16 + 0x1a) - (ushort)DAT_803dc070;
        if (*(short *)((int)pfVar16 + 0x1a) < 1) {
          *(undefined2 *)((int)pfVar16 + 0x1a) = 0;
        }
      }
      if (((*(short *)((int)pfVar16 + 0x1a) != 0) || (puVar10[0x23] != 0x3d6)) &&
         (dVar20 = (double)FUN_80017710((float *)(iVar11 + 0x18),(float *)(puVar10 + 0xc)),
         dVar20 < (double)FLOAT_803e46d0)) {
        dVar20 = (double)(*(float *)(puVar10 + 8) - *(float *)(iVar11 + 0x10));
        if (dVar20 < (double)FLOAT_803e4690) {
          dVar20 = -dVar20;
        }
        if (dVar20 < (double)FLOAT_803e46d4) {
          uVar13 = FUN_80017690(0x910);
          if (uVar13 == 0) {
            *(undefined2 *)(pfVar16 + 0xb) = 0xffff;
            *(undefined2 *)((int)pfVar16 + 0x2e) = 0;
            pfVar16[0xc] = FLOAT_803e4698;
            ObjMsg_SendToObject(dVar20,dVar18,dVar21,param_4,param_5,param_6,param_7,param_8,iVar11,0x7000a
                         ,(uint)puVar10,(uint)(pfVar16 + 0xb),in_r7,in_r8,in_r9,in_r10);
            FUN_80017698(0x910,1);
            *(byte *)(pfVar16 + 10) = *(byte *)(pfVar16 + 10) | 1;
          }
          else {
            local_16c = DAT_803e4688;
            FUN_80294d28(iVar11,(uint)*(byte *)((int)&local_16c +
                                               (uint)*(byte *)((int)pfVar16 + 0x27)));
            *(undefined2 *)(pfVar16 + 4) = 0x50;
            *(undefined2 *)(pfVar16 + 5) = 0;
          }
          if (*(int *)(puVar10 + 0x2a) != 0) {
            ObjHits_DisableObject((int)puVar10);
          }
          FUN_80006824((uint)puVar10,*(ushort *)((int)pfVar16 + 0x1e));
          FUN_80081118((double)FLOAT_803e4698,puVar10,(int)*(short *)(pfVar16 + 8),0x28);
        }
      }
      if ((*(short *)((int)pfVar16 + 0x1a) == 0) && (puVar10[0x23] == 0x3d6)) {
        dVar20 = (double)FUN_80017710((float *)(iVar11 + 0x18),(float *)(puVar10 + 0xc));
        if (dVar20 < (double)FLOAT_803e46d4) {
          dVar20 = (double)(*(float *)(puVar10 + 8) - *(float *)(iVar11 + 0x10));
          if (dVar20 < (double)FLOAT_803e4690) {
            dVar20 = -dVar20;
          }
          if (dVar20 < (double)FLOAT_803e46d4) {
            uVar13 = FUN_80017690(0x1d9);
            if (uVar13 == 0) {
              ObjMsg_SendToObject(dVar20,dVar18,dVar21,param_4,param_5,param_6,param_7,param_8,iVar11,
                           0x60004,(uint)puVar10,1,in_r7,in_r8,in_r9,in_r10);
            }
            fVar2 = FLOAT_803e46d8;
            *(float *)(puVar10 + 6) =
                 FLOAT_803e46d8 * -*(float *)(puVar10 + 0x12) + *(float *)(puVar10 + 6);
            *(float *)(puVar10 + 10) =
                 fVar2 * -*(float *)(puVar10 + 0x16) + *(float *)(puVar10 + 10);
            FUN_80006824((uint)puVar10,0x45);
          }
        }
        iVar17 = ObjHits_GetPriorityHit((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
        if (iVar17 == 0xe) {
          *(undefined2 *)((int)pfVar16 + 0x1a) = 0xfa;
          FUN_80006824((uint)puVar10,0x40);
        }
      }
      else if ((*(short *)((int)pfVar16 + 0x1a) != 0) &&
              ((puVar10[0x23] == 0x3d6 &&
               (iVar17 = ObjHits_GetPriorityHit((int)puVar10,(undefined4 *)0x0,(int *)0x0,(uint *)0x0),
               iVar17 == 0xe)))) {
        FUN_80006824((uint)puVar10,0x46);
        local_170 = DAT_803e4688;
        FUN_80294d28(iVar11,(uint)*(byte *)((int)&local_170 + (uint)*(byte *)((int)pfVar16 + 0x27)))
        ;
        *(undefined2 *)(pfVar16 + 4) = 0x50;
        *(undefined2 *)(pfVar16 + 5) = 0;
      }
    }
  }
LAB_80185bfc:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801858a8
 * EN v1.0 Address: 0x801858A8
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x80185C1C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801858a8(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar4 + 0x24) = 0;
  *(undefined2 *)(iVar4 + 0x14) = *(undefined2 *)(param_2 + 0x1a);
  uVar2 = FUN_80017760(1000,4000);
  *(short *)(iVar4 + 0x16) = (short)uVar2;
  uVar2 = FUN_80017760(0x32,100);
  *(short *)(iVar4 + 0x1c) = (short)uVar2;
  *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(param_2 + 0xc);
  iVar3 = FUN_80017a54(param_1);
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x3d5) {
    uVar2 = FUN_80017760(0,3);
    *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca20)[uVar2];
    *(undefined2 *)(iVar4 + 0x1e) = 0x43;
    *(undefined2 *)(iVar4 + 0x20) = 2;
    *(undefined2 *)(iVar4 + 0x22) = 4;
    *(undefined *)(iVar4 + 0x27) = 2;
    goto LAB_80185d98;
  }
  if (sVar1 < 0x3d5) {
    if (sVar1 == 0x3d3) {
      uVar2 = FUN_80017760(0,2);
      *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca18)[uVar2];
      *(undefined2 *)(iVar4 + 0x1e) = 0x41;
      *(undefined2 *)(iVar4 + 0x20) = 4;
      *(undefined2 *)(iVar4 + 0x22) = 2;
      *(undefined *)(iVar4 + 0x27) = 0;
      goto LAB_80185d98;
    }
    if (0x3d2 < sVar1) {
      uVar2 = FUN_80017760(0,1);
      *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = (&DAT_803dca1c)[uVar2];
      *(undefined2 *)(iVar4 + 0x1e) = 0x42;
      *(undefined2 *)(iVar4 + 0x20) = 1;
      *(undefined2 *)(iVar4 + 0x22) = 5;
      *(undefined *)(iVar4 + 0x27) = 1;
      goto LAB_80185d98;
    }
  }
  *(undefined *)(*(int *)(iVar3 + 0x34) + 8) = 5;
  *(undefined2 *)(iVar4 + 0x1e) = 0x44;
  *(undefined2 *)(iVar4 + 0x20) = 6;
  *(undefined2 *)(iVar4 + 0x22) = 1;
  *(undefined *)(iVar4 + 0x27) = 3;
LAB_80185d98:
  ObjMsg_AllocQueue(param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80185a48
 * EN v1.0 Address: 0x80185A48
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80185DC0
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80185a48(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 in_r10;
  int iVar6;
  undefined8 uVar7;
  undefined auStack_38 [8];
  undefined4 local_30;
  longlong local_20;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  local_30 = *(undefined4 *)(iVar6 + 8);
  (**(code **)(*DAT_803de750 + 4))(param_9,0xf,0,2,0xffffffff,0);
  uVar3 = 0xffffffff;
  uVar4 = 0;
  iVar5 = *DAT_803de754;
  (**(code **)(iVar5 + 4))(param_9,0,auStack_38,2);
  FUN_80006824(param_9,0x71);
  fVar1 = FLOAT_803e46f0;
  *(float *)(param_9 + 0x24) = FLOAT_803e46f0;
  *(float *)(param_9 + 0x2c) = fVar1;
  *(undefined2 *)(iVar6 + 0x10) = 0x32;
  *(undefined2 *)(iVar6 + 0x1a) = 800;
  *(undefined *)(iVar6 + 0x23) = 0;
  *(undefined *)(iVar6 + 0x21) = 0;
  *(undefined4 *)(param_9 + 0xf8) = 0;
  *(undefined4 *)(param_9 + 0xf4) = 2;
  ObjHits_EnableObject(param_9);
  uVar7 = ObjHits_MarkObjectPositionDirty(param_9);
  *(undefined2 *)(iVar6 + 0x1e) = 0;
  if (param_1 < (double)*(float *)(iVar6 + 8)) {
    iVar2 = FUN_80017a98();
    ObjMsg_SendToObject(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60004,param_9
                 ,0,uVar3,uVar4,iVar5,in_r10);
  }
  local_20 = (longlong)(int)*(float *)(iVar6 + 8);
  ObjHitbox_SetCapsuleBounds(param_9,(short)(int)*(float *)(iVar6 + 8),-5,10);
  ObjHits_SetHitVolumeSlot(param_9,0xe,1,0);
  ObjHits_EnableObject(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80185c48
 * EN v1.0 Address: 0x80185C48
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80185F2C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80185c48(void)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80006b0c(DAT_803de750);
  DAT_803de750 = (undefined4*)0x0;
  FUN_80006b0c(DAT_803de754);
  DAT_803de754 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80185c9c
 * EN v1.0 Address: 0x80185C9C
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80185F7C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80185c9c(void)
{
  short sVar1;
  int iVar2;
  int *piVar3;
  char in_r8;
  
  iVar2 = FUN_80286840();
  piVar3 = *(int **)(iVar2 + 0xb8);
  if (((*(short *)(piVar3 + 4) == 0) || (0x32 < *(short *)(piVar3 + 4))) && (*piVar3 == 0)) {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      if (in_r8 == '\0') goto LAB_801860b0;
    }
    else if (in_r8 != -1) goto LAB_801860b0;
    sVar1 = *(short *)((int)piVar3 + 0x1e);
    if (sVar1 != 0) {
      if (sVar1 < 0x3c) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803dc070 * '\n';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b540(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
      else if (sVar1 < 0xf0) {
        *(char *)((int)piVar3 + 0x26) = *(char *)((int)piVar3 + 0x26) + DAT_803dc070 * '\x05';
        if (0x80 < *(byte *)((int)piVar3 + 0x26)) {
          *(undefined *)((int)piVar3 + 0x26) = 0;
        }
        FUN_8003b540(200,0x1e,0x1e,*(undefined *)((int)piVar3 + 0x26));
      }
    }
    FUN_8003b818(iVar2);
  }
LAB_801860b0:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80185dc4
 * EN v1.0 Address: 0x80185DC4
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x801860CC
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80185dc4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  undefined uVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  double in_f31;
  double in_ps31_1;
  float fStack_98;
  float local_94;
  undefined auStack_90 [8];
  undefined4 local_88;
  undefined auStack_78 [8];
  undefined4 local_70;
  undefined auStack_60 [8];
  undefined4 local_58;
  ushort local_48 [4];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined8 local_30;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar2 = (ushort *)FUN_80286840();
  iVar9 = *(int *)(puVar2 + 0x26);
  local_94 = FLOAT_803e46f4;
  (**(code **)(*DAT_803dd6d8 + 0x18))(&local_94);
  piVar8 = *(int **)(puVar2 + 0x5c);
  puVar3 = (ushort *)FUN_80017a98();
  iVar7 = *(int *)(puVar3 + 0x5c);
  dVar10 = (double)FUN_8001771c((float *)(puVar3 + 0xc),(float *)(puVar2 + 0xc));
  if (*(short *)((int)piVar8 + 0x1a) < 1) {
    *(undefined2 *)(piVar8 + 4) = 1;
    *(undefined *)((int)piVar8 + 0x23) = 0;
    *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
    fVar1 = FLOAT_803e46f0;
    *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
    *(float *)(puVar2 + 0x16) = fVar1;
  }
  if (*(short *)((int)piVar8 + 0x1e) != 0) {
    FUN_80006824((uint)puVar2,0x70);
    *(ushort *)((int)piVar8 + 0x1e) = *(short *)((int)piVar8 + 0x1e) - (ushort)DAT_803dc070;
    uVar4 = FUN_80017760(0,2);
    if (uVar4 == 2) {
      in_r7 = 0xffffffff;
      in_r8 = 0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(puVar2,0x51c,0,1);
    }
    if (*(short *)((int)piVar8 + 0x1e) < 1) {
      FUN_80185a48(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)puVar2);
      goto LAB_80186804;
    }
  }
  if (*piVar8 != 0) {
    local_30 = (double)(longlong)(int)(FLOAT_803dc074 * local_94);
    *piVar8 = *piVar8 - (int)(short)(int)(FLOAT_803dc074 * local_94);
    if (*piVar8 < 1) {
      *piVar8 = 0;
      *(undefined2 *)(piVar8 + 4) = 0;
      ObjHits_EnableObject((int)puVar2);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      puVar2[0x7a] = 0;
      puVar2[0x7b] = 0;
    }
    goto LAB_80186804;
  }
  if (*(short *)(piVar8 + 4) != 0) {
    FUN_8000680c((int)puVar2,0x40);
    *(ushort *)(piVar8 + 4) = *(short *)(piVar8 + 4) - (ushort)DAT_803dc070;
    if (*(short *)(piVar8 + 4) < 1) {
      if (piVar8[1] == 0) {
        *piVar8 = 1;
      }
      else {
        *piVar8 = piVar8[1];
      }
    }
    if (*(short *)(piVar8 + 4) < 0x33) goto LAB_80186804;
  }
  if (*(char *)((int)piVar8 + 0x23) == '\0') {
    if (*(char *)((int)piVar8 + 0x21) == '\0') {
      puVar5 = (ushort *)(**(code **)(*DAT_803dd6d0 + 0x3c))();
      uVar6 = 0;
      if (((puVar5 != puVar2) && ((*(byte *)((int)puVar2 + 0xaf) & 1) != 0)) &&
         (*(int *)(puVar2 + 0x7c) == 0)) {
        FUN_80006ba8(0,0x100);
        Obj_GetYawDeltaToObject(puVar2,(int)puVar3,&fStack_98);
        *(undefined2 *)(piVar8 + 3) = 0x8000;
        *(undefined2 *)((int)piVar8 + 0xe) = 0;
        uVar6 = 1;
      }
      *(undefined *)((int)piVar8 + 0x21) = uVar6;
      if (*(char *)((int)piVar8 + 0x21) != '\0') {
        *(undefined *)((int)piVar8 + 0x22) = 1;
        *(undefined2 *)((int)piVar8 + 0x1e) = 600;
      }
      if (*(int *)(puVar2 + 0x7c) == 0) {
        ObjHits_EnableObject((int)puVar2);
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      }
      *(undefined4 *)(puVar2 + 0x40) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(puVar2 + 0x42) = *(undefined4 *)(puVar2 + 10);
      *(undefined4 *)(puVar2 + 0x44) = *(undefined4 *)(puVar2 + 10);
    }
    else {
      uVar11 = ObjHits_DisableObject((int)puVar2);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x10) = *(undefined4 *)(puVar2 + 6);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x14) = *(undefined4 *)(puVar2 + 8);
      *(undefined4 *)(*(int *)(puVar2 + 0x2a) + 0x18) = *(undefined4 *)(puVar2 + 10);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      uVar4 = FUN_80006c00(0);
      if ((uVar4 & 0x100) != 0) {
        *(undefined *)((int)piVar8 + 0x22) = 0;
      }
      if (*(char *)((int)piVar8 + 0x22) != '\0') {
        *(undefined2 *)(piVar8 + 4) = 0;
        *piVar8 = 0;
        ObjMsg_SendToObject(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar3,
                     0x100010,(uint)puVar2,
                     CONCAT22(*(undefined2 *)((int)piVar8 + 0xe),*(undefined2 *)(piVar8 + 3)),in_r7,
                     in_r8,in_r9,in_r10);
      }
      if (*(int *)(puVar2 + 0x7c) == 1) {
        *(undefined *)((int)piVar8 + 0x21) = 2;
      }
      if (((*(char *)((int)piVar8 + 0x21) == '\x02') && (*(int *)(puVar2 + 0x7c) == 0)) &&
         (puVar3[0x50] != 0x447)) {
        *(undefined *)((int)piVar8 + 0x21) = 0;
        *(undefined *)((int)piVar8 + 0x23) = 1;
        local_3c = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x14) = FLOAT_803e46fc * *(float *)(iVar7 + 0x298) + FLOAT_803e46f8;
        *(float *)(puVar2 + 0x16) = FLOAT_803e4704 * *(float *)(iVar7 + 0x298) + FLOAT_803e4700;
        local_38 = local_3c;
        local_34 = local_3c;
        local_40 = FLOAT_803e46f4;
        local_48[2] = 0;
        local_48[1] = 0;
        local_48[0] = *puVar3;
        FUN_80017748(local_48,(float *)(puVar2 + 0x12));
        FUN_80006824((uint)puVar2,0x6a);
      }
      else if ((*(char *)((int)piVar8 + 0x21) == '\x02') && (*(int *)(puVar2 + 0x7c) == 0)) {
        *(undefined *)((int)piVar8 + 0x21) = 0;
        *(undefined *)((int)piVar8 + 0x23) = 2;
        fVar1 = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
        *(float *)(puVar2 + 0x14) = fVar1;
        *(float *)(puVar2 + 0x16) = fVar1;
        FUN_80006824((uint)puVar2,0x6a);
      }
    }
  }
  if ((*(char *)((int)piVar8 + 0x23) == '\0') && (*(char *)((int)piVar8 + 0x21) == '\0')) {
    iVar7 = ObjHits_GetPriorityHit((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if (iVar7 != 0) {
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_58 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_60,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      goto LAB_80186804;
    }
  }
  else if (*(char *)((int)piVar8 + 0x23) != '\0') {
    *(ushort *)((int)piVar8 + 0x1a) = *(short *)((int)piVar8 + 0x1a) - (ushort)DAT_803dc070;
    if (*(char *)((int)piVar8 + 0x23) == '\x01') {
      ObjHits_SetHitVolumeSlot((int)puVar2,0xe,3,0);
      if (FLOAT_803e4708 < *(float *)(puVar2 + 0x14)) {
        *(float *)(puVar2 + 0x14) = FLOAT_803e470c * FLOAT_803dc074 + *(float *)(puVar2 + 0x14);
      }
      ObjHits_EnableObject((int)puVar2);
    }
    if ((*(char *)(*(int *)(puVar2 + 0x2a) + 0xad) != '\0') &&
       (*(char *)((int)piVar8 + 0x23) == '\x01')) {
      *(float *)(puVar2 + 0x14) = FLOAT_803e46f0;
      *(undefined *)((int)piVar8 + 0x23) = 0;
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_70 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_78,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      goto LAB_80186804;
    }
    if ((*(char *)(*(int *)(puVar2 + 0x2a) + 0xad) != '\0') &&
       (*(char *)((int)piVar8 + 0x23) == '\x02')) {
      *(undefined *)((int)piVar8 + 0x23) = 0;
      iVar7 = *(int *)(puVar2 + 0x5c);
      local_88 = *(undefined4 *)(iVar7 + 8);
      (**(code **)(*DAT_803de754 + 4))(puVar2,0,auStack_90,2,0xffffffff,0);
      *(undefined2 *)(iVar7 + 0x1e) = 1;
      *(float *)(puVar2 + 0x14) = FLOAT_803e46f0;
      goto LAB_80186804;
    }
    *(float *)(puVar2 + 6) = *(float *)(puVar2 + 0x12) * FLOAT_803dc074 + *(float *)(puVar2 + 6);
    *(float *)(puVar2 + 8) = *(float *)(puVar2 + 0x14) * FLOAT_803dc074 + *(float *)(puVar2 + 8);
    *(float *)(puVar2 + 10) = *(float *)(puVar2 + 0x16) * FLOAT_803dc074 + *(float *)(puVar2 + 10);
  }
  *(undefined4 *)(puVar2 + 0xc) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(puVar2 + 0xe) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(puVar2 + 0x10) = *(undefined4 *)(puVar2 + 10);
  *(ushort *)((int)piVar8 + 0x16) = *(short *)((int)piVar8 + 0x16) - (ushort)DAT_803dc070;
  if (*(char *)((int)piVar8 + 0x21) != '\0') {
    dVar10 = FUN_80017708((float *)(puVar2 + 0xc),(float *)(iVar9 + 8));
    fVar1 = FLOAT_803e46f0;
    local_30 = (double)CONCAT44(0x43300000,
                                (int)*(short *)((int)piVar8 + 0x12) *
                                (int)*(short *)((int)piVar8 + 0x12) ^ 0x80000000);
    if ((double)(float)(local_30 - DOUBLE_803e4710) <= dVar10) {
      *(float *)(puVar2 + 0x12) = FLOAT_803e46f0;
      *(float *)(puVar2 + 0x16) = fVar1;
      *(undefined2 *)(piVar8 + 4) = 500;
      *(undefined *)((int)piVar8 + 0x23) = 0;
      puVar2[0x7c] = 0;
      puVar2[0x7d] = 0;
      ObjHits_EnableObject((int)puVar2);
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xf7;
      ObjHits_ClearHitVolumes((int)puVar2);
    }
  }
LAB_80186804:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018671c
 * EN v1.0 Address: 0x8018671C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80186824
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018671c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80186720
 * EN v1.0 Address: 0x80186720
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80186A04
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186720(int param_1)
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
 * Function: FUN_80186748
 * EN v1.0 Address: 0x80186748
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80186A38
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80186748(int param_1)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  uVar1 = FUN_80017a98();
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar2 = FUN_80294cc4(uVar1,3);
  if (uVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(char *)(iVar5 + 0xc) < '\0') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    iVar3 = FUN_80294d6c(uVar1);
    if (iVar3 == 0x5bd) {
      FUN_80294d68(uVar1,-1);
    }
    FUN_80017698((int)*(short *)(iVar4 + 0x1e),1);
  }
  else {
    iVar4 = FUN_80294d6c(uVar1);
    if ((iVar4 == 0x5bd) && (*(int *)(iVar5 + 8) == -1)) {
      *(undefined4 *)(iVar5 + 8) = 0;
    }
  }
  if ((*(int *)(iVar5 + 8) != -1) &&
     (iVar4 = *(int *)(iVar5 + 8) - (uint)DAT_803dc070, *(int *)(iVar5 + 8) = iVar4, iVar4 < 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    iVar4 = FUN_80017a90();
    if (iVar4 != 0) {
      FUN_8013651c(iVar4);
    }
    *(byte *)(iVar5 + 0xc) = *(byte *)(iVar5 + 0xc) & 0x7f | 0x80;
    *(undefined4 *)(iVar5 + 8) = 0xffffffff;
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_80185B70(void) {}
void fn_80186464(void) {}
void fn_80186468(void) {}
void fn_8018647C(void) {}
void fn_80186480(void) {}
void fn_80186484(void) {}
void fn_80186488(void) {}
void fn_8018648C(void) {}
void fn_80186490(void) {}
void fn_80186494(void) {}
void portalspelldoor_free(void) {}
void portalspelldoor_hitDetect(void) {}
void portalspelldoor_release(void) {}
void portalspelldoor_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801859C4(void) { return 0x2c; }
int fn_801859CC(void) { return 0x0; }
int fn_8018646C(void) { return 0x0; }
int fn_80186474(void) { return 0x0; }
int portalspelldoor_getExtraSize(void) { return 0x10; }
int portalspelldoor_func08(void) { return 0x0; }
int fn_80186ADC(void) { return 0x74; }
int fn_80186AE4(void) { return 0x0; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E3A88;
extern void fn_8003B8F4(f32);
#pragma peephole off
void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E3A88); }
#pragma peephole reset
