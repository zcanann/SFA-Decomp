#include "ghidra_import.h"
#include "main/dll/dll_153.h"

extern undefined8 FUN_80006824();
extern uint FUN_80006ba0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern double FUN_80017708();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_80037bd4();
extern int FUN_800384ec();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_80181b50();
extern undefined4 FUN_801816f8();
extern undefined4 FUN_801826e8();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bec();
extern byte FUN_80294c20();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de740;
extern f64 DOUBLE_803e4600;
extern f64 DOUBLE_803e4638;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e45c8;
extern f32 FLOAT_803e45d0;
extern f32 FLOAT_803e45e8;
extern f32 FLOAT_803e45f0;
extern f32 FLOAT_803e460c;
extern f32 FLOAT_803e4610;
extern f32 FLOAT_803e4614;
extern f32 FLOAT_803e4618;
extern f32 FLOAT_803e461c;
extern f32 FLOAT_803e4620;
extern f32 FLOAT_803e4624;
extern f32 FLOAT_803e4628;
extern f32 FLOAT_803e462c;
extern f32 FLOAT_803e4630;

/*
 * --INFO--
 *
 * Function: dll153_updateExploderState
 * EN v1.0 Address: 0x801826E8
 * EN v1.0 Size: 3072b
 * EN v1.1 Address: 0x80182C40
 * EN v1.1 Size: 2476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll153_updateExploderState
          (undefined8 param_1,double param_2,double param_3,undefined8 param_4,
           undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar1;
  bool bVar2;
  float fVar3;
  double dVar4;
  int iVar5;
  uint uVar6;
  ushort *puVar7;
  int iVar8;
  uint uVar9;
  byte bVar10;
  undefined4 in_r6;
  undefined4 uVar11;
  undefined4 in_r7;
  undefined4 uVar12;
  undefined4 in_r8;
  undefined4 uVar13;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined uVar14;
  undefined2 *puVar15;
  int iVar16;
  double extraout_f1;
  double dVar17;
  undefined8 uVar18;
  float local_48;
  ushort local_44 [4];
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar6 = FUN_80286840();
  puVar7 = (ushort *)FUN_80017a98();
  iVar16 = *(int *)(uVar6 + 0x4c);
  local_48 = FLOAT_803e45e8;
  (**(code **)(*DAT_803dd6d8 + 0x18))(&local_48);
  puVar15 = *(undefined2 **)(uVar6 + 0xb8);
  iVar8 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar16 + 0x14));
  if (iVar8 != 0) {
    iVar8 = *(int *)(puVar7 + 0x5c);
    dVar17 = extraout_f1;
    if ((short)puVar15[9] < 1) {
      puVar15[9] = 800;
      puVar15[5] = 1;
      *(undefined *)((int)puVar15 + 9) = 0;
      *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
      dVar17 = (double)FUN_801816f8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                    param_8,uVar6,puVar7,(int)puVar15,in_r6,in_r7,in_r8,in_r9,in_r10
                                   );
      fVar3 = FLOAT_803e45d0;
      *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
      *(float *)(uVar6 + 0x2c) = fVar3;
    }
    dVar4 = DOUBLE_803e4638;
    if (*(int *)(puVar15 + 10) == 0) {
      if (*(char *)((int)puVar15 + 5) != '\x02') {
        param_3 = (double)FLOAT_803e4610;
        param_2 = (double)FLOAT_803dc074;
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(uVar6 + 0x36));
        iVar5 = (int)(param_3 * param_2 + (double)(float)(local_28 - DOUBLE_803e4638));
        local_20 = (double)(longlong)iVar5;
        if (0xff < iVar5) {
          iVar5 = 0xff;
        }
        *(char *)(uVar6 + 0x36) = (char)iVar5;
        dVar17 = dVar4;
      }
      if (puVar15[5] != 0) {
        dVar17 = (double)ObjHits_DisableObject(uVar6);
        puVar15[5] = puVar15[5] - (ushort)DAT_803dc070;
        if ((short)puVar15[5] < 1) {
          if (*(int *)(puVar15 + 0xc) == 0) {
            *(undefined4 *)(puVar15 + 10) = 1;
          }
          else {
            *(int *)(puVar15 + 10) = *(int *)(puVar15 + 0xc);
          }
          local_20 = (double)CONCAT44(0x43300000,*(uint *)(puVar15 + 0xc) ^ 0x80000000);
          dVar17 = (double)(**(code **)(*DAT_803dd72c + 100))
                                     ((double)(float)(local_20 - DOUBLE_803e4600),
                                      *(undefined4 *)(iVar16 + 0x14));
          *(undefined4 *)(uVar6 + 0xc) = *(undefined4 *)(iVar16 + 8);
          *(undefined4 *)(uVar6 + 0x10) = *(undefined4 *)(iVar16 + 0xc);
          *(undefined4 *)(uVar6 + 0x14) = *(undefined4 *)(iVar16 + 0x10);
          *(undefined4 *)(uVar6 + 0x80) = *(undefined4 *)(iVar16 + 8);
          *(undefined4 *)(uVar6 + 0x84) = *(undefined4 *)(iVar16 + 0xc);
          *(undefined4 *)(uVar6 + 0x88) = *(undefined4 *)(iVar16 + 0x10);
          fVar3 = FLOAT_803e45d0;
          *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
          *(float *)(uVar6 + 0x28) = fVar3;
          *(float *)(uVar6 + 0x2c) = fVar3;
        }
        if ((short)puVar15[5] < 0x33) goto LAB_801835d4;
      }
      if (*(char *)((int)puVar15 + 9) == '\x01') {
        puVar15[9] = puVar15[9] - (ushort)DAT_803dc070;
        if (*(char *)((int)puVar15 + 9) == '\x01') {
          ObjHits_SetHitVolumeSlot(uVar6,0xe,1,0);
          if (FLOAT_803e462c < *(float *)(uVar6 + 0x28)) {
            *(float *)(uVar6 + 0x28) = FLOAT_803e4630 * FLOAT_803dc074 + *(float *)(uVar6 + 0x28);
          }
          ObjHits_EnableObject(uVar6);
        }
        *(float *)(uVar6 + 0xc) =
             *(float *)(uVar6 + 0x24) * FLOAT_803dc074 + *(float *)(uVar6 + 0xc);
        *(float *)(uVar6 + 0x10) =
             *(float *)(uVar6 + 0x28) * FLOAT_803dc074 + *(float *)(uVar6 + 0x10);
        param_2 = (double)*(float *)(uVar6 + 0x2c);
        *(float *)(uVar6 + 0x14) =
             (float)(param_2 * (double)FLOAT_803dc074 + (double)*(float *)(uVar6 + 0x14));
        dVar17 = (double)FUN_801826e8();
        fVar3 = FLOAT_803e45d0;
        cVar1 = *(char *)(*(int *)(uVar6 + 0x54) + 0xad);
        if ((cVar1 == '\0') || (*(char *)((int)puVar15 + 9) != '\x01')) {
          if ((cVar1 != '\0') && (*(char *)((int)puVar15 + 9) == '\x02')) {
            *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
            *(float *)(uVar6 + 0x2c) = fVar3;
            puVar15[5] = 500;
            *(undefined *)((int)puVar15 + 9) = 0;
            *(undefined4 *)(uVar6 + 0xf8) = 0;
            ObjHits_EnableObject(uVar6);
            *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
            dVar17 = (double)ObjHits_ClearHitVolumes(uVar6);
          }
        }
        else {
          local_38 = *(float *)(uVar6 + 0xc);
          local_34 = *(float *)(uVar6 + 0x10);
          local_30 = *(float *)(uVar6 + 0x14);
          FUN_80081120(uVar6,local_44,1,(int *)0x0);
          uVar11 = 2;
          uVar12 = 0xffffffff;
          uVar13 = 0;
          iVar8 = *DAT_803de740;
          (**(code **)(iVar8 + 4))(uVar6,1,0);
          uVar18 = FUN_80006824(uVar6,puVar15[8]);
          puVar15[5] = 0x32;
          *(undefined *)((int)puVar15 + 9) = 0;
          *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
          FUN_801816f8(uVar18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,puVar7,
                       (int)puVar15,uVar11,uVar12,uVar13,iVar8,in_r10);
          fVar3 = FLOAT_803e45d0;
          *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
          *(float *)(uVar6 + 0x2c) = fVar3;
          dVar17 = (double)ObjHits_ClearHitVolumes(uVar6);
        }
      }
      else if (*(char *)((int)puVar15 + 5) == '\0') {
        uVar14 = 0;
        uVar9 = FUN_80006ba0(0);
        if ((((uVar9 & 0x100) == 0) && (*(int *)(uVar6 + 0xf8) == 0)) &&
           (iVar8 = FUN_800384ec(uVar6), iVar8 != 0)) {
          *puVar15 = 0x8000;
          puVar15[1] = 0;
          dVar17 = (double)ObjHits_DisableObject(uVar6);
          uVar14 = 1;
        }
        *(undefined *)((int)puVar15 + 5) = uVar14;
        if (*(char *)((int)puVar15 + 5) != '\0') {
          *(undefined *)(puVar15 + 3) = 1;
        }
        if (*(int *)(uVar6 + 0xf8) == 0) {
          dVar17 = (double)ObjHits_EnableObject(uVar6);
          if ((*(char *)(puVar15 + 0x10) == '\0') ||
             (bVar10 = FUN_80294c20((int)puVar7), bVar10 != 0)) {
            *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xef;
          }
          else {
            *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 0x10;
          }
        }
        *(undefined4 *)(uVar6 + 0x80) = *(undefined4 *)(uVar6 + 0xc);
        *(undefined4 *)(uVar6 + 0x84) = *(undefined4 *)(uVar6 + 0x14);
        *(undefined4 *)(uVar6 + 0x88) = *(undefined4 *)(uVar6 + 0x14);
      }
      else {
        ObjHits_DisableObject(uVar6);
        *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
        uVar9 = FUN_80294db4((int)puVar7);
        if ((uVar9 & 0x4000) == 0) {
          dVar17 = (double)FUN_8011e868(4);
        }
        else {
          dVar17 = (double)FUN_8011e868(5);
        }
        uVar9 = FUN_80006c00(0);
        if ((uVar9 & 0x100) != 0) {
          uVar9 = FUN_80294bec((int)puVar7);
          if (uVar9 == 0) {
            dVar17 = (double)FUN_80006824(0,0x10a);
          }
          else {
            *(undefined *)(puVar15 + 3) = 0;
            dVar17 = (double)FUN_80006ba8(0,0x100);
          }
        }
        if (*(int *)(uVar6 + 0xf8) == 1) {
          *(undefined *)((int)puVar15 + 5) = 2;
        }
        if (((*(char *)((int)puVar15 + 5) == '\x02') && (*(int *)(uVar6 + 0xf8) == 0)) ||
           ((*(char *)(puVar15 + 0x10) != '\0' && (bVar10 = FUN_80294c20((int)puVar7), bVar10 == 0))
           )) {
          uVar9 = FUN_80294ce8((int)puVar7);
          if (uVar9 == 0) {
            uVar9 = FUN_80294cf0((int)puVar7);
            if (uVar9 == 0) {
              *(undefined *)((int)puVar15 + 5) = 0;
              *(undefined *)((int)puVar15 + 9) = 1;
              *(float *)(uVar6 + 0x28) = FLOAT_803e4620 * *(float *)(iVar8 + 0x298) + FLOAT_803e461c
              ;
              param_2 = (double)FLOAT_803e4628;
              *(float *)(uVar6 + 0x2c) =
                   (float)(param_2 * (double)*(float *)(iVar8 + 0x298) + (double)FLOAT_803e4624);
              local_38 = FLOAT_803e45d0;
              local_34 = FLOAT_803e45d0;
              local_30 = FLOAT_803e45d0;
              local_3c = FLOAT_803e45e8;
              local_44[2] = 0;
              local_44[1] = 0;
              local_44[0] = *puVar7;
              FUN_80017748(local_44,(float *)(uVar6 + 0x24));
              dVar17 = (double)FUN_80006824(uVar6,0x6b);
              *(undefined *)(puVar15 + 3) = 0;
              *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) | 8;
            }
            else {
              *(undefined *)((int)puVar15 + 5) = 0;
              *(undefined *)((int)puVar15 + 9) = 2;
              fVar3 = FLOAT_803e45d0;
              *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
              *(float *)(uVar6 + 0x28) = fVar3;
              *(float *)(uVar6 + 0x2c) = fVar3;
              ObjHits_EnableObject(uVar6);
              *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
              dVar17 = (double)ObjHits_ClearHitVolumes(uVar6);
            }
          }
          else {
            *(undefined *)((int)puVar15 + 5) = 0;
            *(undefined *)((int)puVar15 + 9) = 1;
            *(float *)(uVar6 + 0x28) = FLOAT_803e4614 * *(float *)(iVar8 + 0x298) + FLOAT_803e45f0;
            param_2 = (double)FLOAT_803e4618;
            *(float *)(uVar6 + 0x2c) =
                 (float)(param_2 * (double)*(float *)(iVar8 + 0x298) + (double)FLOAT_803e460c);
            local_38 = FLOAT_803e45d0;
            local_34 = FLOAT_803e45d0;
            local_30 = FLOAT_803e45d0;
            local_3c = FLOAT_803e45e8;
            local_44[2] = 0;
            local_44[1] = 0;
            local_44[0] = *puVar7;
            if (*(short **)(puVar7 + 0x18) != (short *)0x0) {
              local_44[0] = local_44[0] + **(short **)(puVar7 + 0x18);
            }
            FUN_80017748(local_44,(float *)(uVar6 + 0x24));
            dVar17 = (double)FUN_80006824(uVar6,0x6b);
          }
        }
        if (*(char *)(puVar15 + 3) != '\0') {
          puVar15[5] = 0;
          *(undefined4 *)(puVar15 + 10) = 0;
          FUN_80037bd4(dVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)puVar7,
                       0x100010,uVar6,CONCAT22(puVar15[1],*puVar15),in_r7,in_r8,in_r9,in_r10);
        }
      }
      puVar15[7] = puVar15[7] - (ushort)DAT_803dc070;
      if (*(char *)((int)puVar15 + 5) == '\0') {
        FUN_80181b50(dVar17,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,puVar7,
                     (int)puVar15);
      }
      else {
        dVar17 = FUN_80017708((float *)(uVar6 + 0x18),(float *)(iVar16 + 8));
        fVar3 = FLOAT_803e45d0;
        local_20 = (double)CONCAT44(0x43300000,
                                    (int)(short)puVar15[6] * (int)(short)puVar15[6] ^ 0x80000000);
        if ((double)(float)(local_20 - DOUBLE_803e4600) <= dVar17) {
          *(float *)(uVar6 + 0x24) = FLOAT_803e45d0;
          *(float *)(uVar6 + 0x2c) = fVar3;
          puVar15[5] = 500;
          *(undefined *)((int)puVar15 + 9) = 0;
          *(undefined4 *)(uVar6 + 0xf8) = 0;
          ObjHits_EnableObject(uVar6);
          *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
          ObjHits_ClearHitVolumes(uVar6);
        }
      }
      if (((short)puVar15[7] < 1) && (*(char *)((int)puVar15 + 5) != '\0')) {
        cVar1 = *(char *)(puVar15 + 0xf);
        if ((cVar1 == '\x05') || (cVar1 == '\x06')) {
          FUN_80006824(uVar6,0x6c);
          uVar9 = FUN_80017760(0,100);
          puVar15[7] = (short)uVar9 + 300;
        }
        else if (((byte)(cVar1 - 1U) < 2) || (cVar1 == '\x03')) {
          FUN_80006824(uVar6,0x6d);
          uVar9 = FUN_80017760(0,100);
          puVar15[7] = (short)uVar9 + 300;
        }
      }
      if (*(int *)(uVar6 + 0xf8) == 0) {
        *(ushort *)(uVar6 + 6) = *(ushort *)(uVar6 + 6) & 0xbfff;
      }
    }
    else {
      bVar2 = false;
      *(undefined *)(uVar6 + 0x36) = 0;
      local_28 = (double)(longlong)(int)(FLOAT_803dc074 * local_48);
      *(int *)(puVar15 + 10) = *(int *)(puVar15 + 10) - (int)(short)(int)(FLOAT_803dc074 * local_48)
      ;
      if (*(int *)(puVar15 + 10) < 1) {
        iVar8 = FUN_80017a98();
        dVar17 = (double)FUN_8001771c((float *)(uVar6 + 0x18),(float *)(iVar8 + 0x18));
        if (((double)FLOAT_803e45c8 < dVar17) && (puVar15[0xe] == -1)) {
          bVar2 = true;
        }
        if (bVar2) {
          *(undefined4 *)(puVar15 + 10) = 0;
          puVar15[5] = 0;
          ObjHits_EnableObject(uVar6);
          ObjHits_SyncObjectPositionIfDirty(uVar6);
          *(byte *)(uVar6 + 0xaf) = *(byte *)(uVar6 + 0xaf) & 0xf7;
          *(ushort *)(uVar6 + 6) = *(ushort *)(uVar6 + 6) & 0xbfff;
        }
        else {
          *(undefined4 *)(puVar15 + 10) = 1;
        }
      }
    }
  }
LAB_801835d4:
  FUN_8028688c();
  return;
}
