#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/mediumbasket.h"
#include "main/effect_interfaces.h"
#include "main/objanim.h"
#include "main/objhits_types.h"

extern undefined8 FUN_80003494();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006a54();
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017964();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjMsg_SendToObjects();
extern uint ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8006fb00();
extern undefined4 FUN_8014d3d0();
extern undefined8 FUN_8014d4c8();
extern undefined4 FUN_8015a320();
extern undefined4 FUN_8015a6c0();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_803209d0;
extern undefined4 DAT_803209e0;
extern undefined DAT_80320a88;
extern undefined4 DAT_80320a98;
extern undefined4 DAT_803ad188;
extern undefined4 DAT_803ad1a8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc990;
extern undefined4 DAT_803dc994;
extern undefined4 DAT_803dc998;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern u8 lbl_803DDA78;
extern u8 lbl_803DDA79;
extern f64 DOUBLE_803e3948;
extern f64 DOUBLE_803e3978;
extern f64 DOUBLE_803e39a0;
extern f64 DOUBLE_803e3a00;
extern f32 lbl_803DC074;
extern f32 lbl_803E3958;
extern f32 lbl_803E395C;
extern f32 lbl_803E3960;
extern f32 lbl_803E3964;
extern f32 lbl_803E3968;
extern f32 lbl_803E396C;
extern f32 lbl_803E3970;
extern f32 lbl_803E3980;
extern f32 lbl_803E3984;
extern f32 lbl_803E3988;
extern f32 lbl_803E398C;
extern f32 lbl_803E3990;
extern f32 lbl_803E3994;
extern f32 lbl_803E3998;
extern f32 lbl_803E39A8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39B0;
extern f32 lbl_803E39B4;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f32 lbl_803E39C8;
extern f32 lbl_803E39CC;
extern f32 lbl_803E39D0;
extern f32 lbl_803E39D4;
extern f32 lbl_803E39D8;
extern f32 lbl_803E39DC;
extern f32 lbl_803E39E0;
extern f32 lbl_803E39E4;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39EC;
extern f32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803E3A44;
extern f32 lbl_803E3A48;
extern void* PTR_DAT_80320998;

/*
 * --INFO--
 *
 * Function: FUN_8015ad60
 * EN v1.0 Address: 0x8015AD60
 * EN v1.0 Size: 940b
 * EN v1.1 Address: 0x8015ADD0
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015ad60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  int iVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar3;
  undefined8 uVar4;
  double dVar5;
  
  puVar3 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
  if (param_9[0x50] == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    ObjHits_DisableObject((int)param_9);
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    ObjHits_EnableObject((int)param_9);
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_10 + 0x33a) < 2)) {
    if ((*(short *)(param_10 + 0x338) == 0) && (uVar2 = randomGetRange(0,0x14), 9 < (int)uVar2)) {
      *(undefined *)(param_10 + 0x33a) = 7;
    }
    else {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + '\x01';
    if ((byte)(&DAT_803dc994)[*(ushort *)(param_10 + 0x338)] < *(byte *)(param_10 + 0x33a)) {
      *(undefined *)(param_10 + 0x33a) = (&DAT_803dc990)[*(ushort *)(param_10 + 0x338)];
    }
    if (*(ushort *)(param_10 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d4c8((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
    }
    else {
      iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      uVar4 = FUN_8014d4c8((double)*(float *)(puVar3 + iVar1),param_2,param_3,param_4,param_5,
                           param_6,param_7,param_8,(int)param_9,param_10,
                           (uint)(byte)puVar3[iVar1 + 9],0,0,in_r8,in_r9,in_r10);
    }
    if (param_9[0x50] == 9) {
      FUN_8015a320(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else if (param_9[0x50] == 1) {
      uVar2 = randomGetRange(0,(uint)*(byte *)(param_10 + 0x33b));
      randomGetRange(0xffff8000,0x7fff);
      dVar5 = (double)FUN_80293f90();
      *(float *)(param_9 + 6) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 8));
      dVar5 = (double)FUN_80294964();
      *(float *)(param_9 + 10) =
           (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3948
                                  ) * dVar5 + (double)*(float *)(*(int *)(param_9 + 0x26) + 0x10));
      FUN_8014d3d0(param_9,param_10,1,0);
    }
  }
  FUN_8014d3d0(param_9,param_10,(uint)(byte)(&DAT_803dc998)[*(ushort *)(param_10 + 0x338)],0);
  FUN_8015a6c0((uint)param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b10c
 * EN v1.0 Address: 0x8015B10C
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x8015B0A8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b10c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  int iVar1;
  undefined *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  puVar2 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (((GameObject *)param_9)->anim.currentMove == 7) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (((GameObject *)param_9)->anim.currentMove != 0) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    FUN_8014d4c8((double)*(float *)(puVar2 + iVar1),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,param_10,(uint)(byte)puVar2[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
  }
  FUN_8015a6c0(param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b218
 * EN v1.0 Address: 0x8015B218
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8015B16C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b218(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  ((GroundBaddieState *)param_2)->baddie.unk2AC = lbl_803E3958;
  *(char *)(param_2 + 0x33b) = (char)(int)((GroundBaddieState *)param_2)->baddie.unk2A8;
  ((GroundBaddieState *)param_2)->baddie.unk2A8 = lbl_803E395C;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42003;
  ((GroundBaddieState *)param_2)->baddie.unk308 = lbl_803E3960;
  ((GroundBaddieState *)param_2)->baddie.unk300 = lbl_803E3964;
  ((GroundBaddieState *)param_2)->baddie.unk304 = lbl_803E3968;
  ((GroundBaddieState *)param_2)->baddie.unk320 = 0;
  fVar1 = lbl_803E396C;
  *(float *)(param_2 + 0x314) = lbl_803E396C;
  ((GroundBaddieState *)param_2)->baddie.unk321 = 10;
  ((GroundBaddieState *)param_2)->baddie.unk318 = fVar1;
  ((GroundBaddieState *)param_2)->baddie.unk322 = 7;
  ((GroundBaddieState *)param_2)->baddie.unk31C = fVar1;
  ((GroundBaddieState *)param_2)->baddie.unk33A = 1;
  uVar2 = countLeadingZeros(0x84b - ((GameObject *)param_1)->anim.seqId);
  *(short *)(param_2 + 0x338) = (short)(uVar2 >> 5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b2cc
 * EN v1.0 Address: 0x8015B2CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8015B208
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b2cc(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b2d0
 * EN v1.0 Address: 0x8015B2D0
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8015B20C
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b2d0(short *param_1,int param_2)
{
  if (*(char *)(param_2 + 0x33b) == '\0') {
    ObjGroup_AddObject((int)param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 1;
  }
  ObjHits_SetHitVolumeSlot((int)param_1,10,1,0);
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  *param_1 = *param_1 + -0x100;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b34c
 * EN v1.0 Address: 0x8015B34C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8015B288
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b34c(short *param_1,int param_2)
{
  if (*(char *)(param_2 + 0x33b) != '\0') {
    ObjGroup_RemoveObject((int)param_1,0x50);
    *(undefined *)(param_2 + 0x33b) = 0;
  }
  *param_1 = (short)(int)-(lbl_803E3970 * lbl_803DC074 -
                          (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                 DOUBLE_803e3978));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b3d4
 * EN v1.0 Address: 0x8015B3D4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8015B314
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015b3d4(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  ((GroundBaddieState *)param_2)->baddie.unk2AC = lbl_803E3980;
  *(char *)(param_2 + 0x33b) = (char)(int)((GroundBaddieState *)param_2)->baddie.unk2A8;
  ((GroundBaddieState *)param_2)->baddie.unk2A8 = lbl_803E3984;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42001;
  ((GroundBaddieState *)param_2)->baddie.unk308 = lbl_803E3988;
  ((GroundBaddieState *)param_2)->baddie.unk300 = lbl_803E398C;
  ((GroundBaddieState *)param_2)->baddie.unk304 = lbl_803E3990;
  ((GroundBaddieState *)param_2)->baddie.unk320 = 0;
  fVar1 = lbl_803E3994;
  *(float *)(param_2 + 0x314) = lbl_803E3994;
  ((GroundBaddieState *)param_2)->baddie.unk321 = 5;
  ((GroundBaddieState *)param_2)->baddie.unk318 = fVar1;
  ((GroundBaddieState *)param_2)->baddie.unk322 = 7;
  ((GroundBaddieState *)param_2)->baddie.unk31C = fVar1;
  ((GroundBaddieState *)param_2)->baddie.unk33A = 1;
  ((GroundBaddieState *)param_2)->baddie.inWhirlpoolGroup = 0;
  iVar2 = FUN_80017a54(param_1);
  FUN_80017964(iVar2,FUN_8006fb00);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b47c
 * EN v1.0 Address: 0x8015B47C
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x8015B3BC
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015b47c(int param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined8 local_18;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) == '\0') {
      if ((*(short *)(param_2 + 0x274) == 7) && ((int)*(float *)(param_2 + 0x2c0) < 0x37)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
      }
    }
    else {
      uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe));
      iVar4 = (**(code **)(*DAT_803dd738 + 0x44))
                        ((double)(float)(local_18 - DOUBLE_803e39a0),param_1,param_2,1);
      if (iVar4 != 0) {
        return 5;
      }
      if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
        if (*(short *)(param_2 + 0x274) == 6) {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
        }
      }
      else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
      }
      else {
        iVar4 = *(int *)(iVar3 + 0x40c);
        if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
        }
        else {
          sVar1 = *(short *)(iVar4 + 4);
          *(short *)(iVar4 + 4) = sVar1 + 1;
          (**(code **)(*DAT_803dd70c + 0x14))
                    (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
        }
        if (6 < *(short *)(iVar4 + 4)) {
          *(undefined2 *)(iVar4 + 4) = 0;
        }
      }
    }
  }
  else if ((int)*(float *)(param_2 + 0x2c0) < 0x38) {
    if (*(short *)(param_2 + 0x274) == 6) {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,5);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
    }
  }
  else if ((*(byte *)(iVar3 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,7);
  }
  else {
    iVar4 = *(int *)(iVar3 + 0x40c);
    if ((*(byte *)(iVar3 + 0x404) & 0x10) == 0) {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209d0 + sVar1 * 2));
    }
    else {
      sVar1 = *(short *)(iVar4 + 4);
      *(short *)(iVar4 + 4) = sVar1 + 1;
      (**(code **)(*DAT_803dd70c + 0x14))
                (param_1,param_2,(int)*(short *)(&DAT_803209e0 + sVar1 * 2));
    }
    if (6 < *(short *)(iVar4 + 4)) {
      *(undefined2 *)(iVar4 + 4) = 0;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015b7f0
 * EN v1.0 Address: 0x8015B7F0
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x8015B74C
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015b7f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  
  iVar5 = *(int *)&((GameObject *)param_9)->extra;
  if ((*(char *)(param_10 + 0x346) == '\0') ||
     (uVar3 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998), (uVar3 & 1) != 0)) {
    if (*(char *)(param_10 + 0x27b) == '\0') {
      sVar1 = *(short *)(iVar5 + 0x402);
      if (sVar1 == 3) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,4);
      }
      else if (sVar1 == 4) {
        if ((*(float *)(param_10 + 0x2c0) < lbl_803E39A8) && (*(char *)(param_10 + 0x346) != '\0')
           ) {
          if (*(byte *)(iVar5 + 0x406) < 0x33) {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,1);
          }
          else {
            (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0);
          }
        }
      }
      else if (sVar1 == 1) {
        return 8;
      }
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0xb);
    }
    fVar2 = lbl_803E39AC;
    *(float *)(param_10 + 0x290) = lbl_803E39AC;
    *(float *)(param_10 + 0x28c) = fVar2;
    FUN_80003494(iVar5 + 0x35c,param_9 + 0xc,0xc);
    uVar6 = FUN_80003494(iVar5 + 0x368,*(int *)(param_10 + 0x2d0) + 0xc,0xc);
    FUN_80006a54(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (*(char *)(iVar5 + 0x381) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)lbl_803E39AC,(double)lbl_803E39AC,(double)lbl_803E39B0,param_9,
                 param_10);
    }
    else {
      (**(code **)(*DAT_803dd70c + 0x1c))
                ((double)*(float *)(iVar5 + 0x374),(double)*(float *)(iVar5 + 0x37c),
                 (double)lbl_803E39B4,(double)lbl_803E39B8,(double)lbl_803E39B0,param_9,
                 param_10);
    }
    if ((0x78 < *(short *)(param_10 + 0x32e)) &&
       (iVar5 = (**(code **)(*DAT_803dd738 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar5 + 0x3fe)) -
                                          DOUBLE_803e39a0),param_9,param_10,1), iVar5 != 0)) {
      return 5;
    }
    uVar4 = 0;
  }
  else {
    uVar4 = 5;
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8015badc
 * EN v1.0 Address: 0x8015BADC
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x8015B9D0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015badc(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,3);
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    if (*(short *)(param_2 + 0x274) != 3) {
      return 8;
    }
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bb80
 * EN v1.0 Address: 0x8015BB80
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8015BA78
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bb80(undefined4 param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bbc8
 * EN v1.0 Address: 0x8015BBC8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x8015BAC0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bbc8(int param_1,int param_2)
{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)&((GameObject *)param_1)->extra;
    ((GroundBaddieState *)iVar1)->unk405 = 0;
    GameBit_Set((int)((GroundBaddieState *)iVar1)->gameBitB,0);
    GameBit_Set((int)((GroundBaddieState *)iVar1)->gameBitA,1);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bc20
 * EN v1.0 Address: 0x8015BC20
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8015BB1C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015bc20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      uVar1 = ObjMsg_SendToObjects(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,
                           param_9,0xe0000,param_9,in_r8,in_r9,in_r10);
      if (*(int *)&((GameObject *)param_9)->anim.placementData == 0) {
        FUN_80017ac8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,0xd);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    ObjHits_DisableObject(param_9);
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015bd9c
 * EN v1.0 Address: 0x8015BD9C
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x8015BBF4
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015bd9c(int param_1,int param_2)
{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x354) < '\x01') {
    uVar1 = 3;
  }
  else {
    if (*(char *)(param_2 + 0x346) != '\0') {
      if (*(short *)(param_2 + 0x274) != 0xc) {
        return 8;
      }
      if (*(byte *)(*(int *)&((GameObject *)param_1)->extra + 0x406) < 0x33) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8015be40
 * EN v1.0 Address: 0x8015BE40
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x8015BC98
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8015be40(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  fVar1 = lbl_803E39AC;
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) != '\0') {
      ((GroundBaddieState *)param_2)->baddie.animSpeedB = lbl_803E39AC;
      ((GroundBaddieState *)param_2)->baddie.animSpeedA = fVar1;
      if (((GroundBaddieState *)iVar3)->aggression < 0x33) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
      else if ((((GroundBaddieState *)param_2)->baddie.targetDistance <
                lbl_803E39BC *
                (float)((double)CONCAT44(0x43300000,(uint)((GroundBaddieState *)iVar3)->aggroRange) -
                       DOUBLE_803e39a0)) || ((((GroundBaddieState *)iVar3)->configFlags & 2) != 0)) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_1,param_2,4);
      uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998,param_1,param_2);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      if ((lbl_803E39BC *
           (float)((double)CONCAT44(0x43300000,(uint)((GroundBaddieState *)iVar3)->aggroRange) - DOUBLE_803e39a0)
           <= ((GroundBaddieState *)param_2)->baddie.targetDistance) && ((((GroundBaddieState *)iVar3)->configFlags & 2) == 0)) {
        return 7;
      }
      return 8;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c00c
 * EN v1.0 Address: 0x8015C00C
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8015BE64
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c00c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  fVar1 = lbl_803E39AC;
  dVar4 = (double)lbl_803E39AC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,param_12,
                 param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if ((*(byte *)(param_10 + 0x356) & 1) == 0) {
    iVar2 = FUN_80017a98();
    if (*(short *)(iVar2 + 0x46) == 0) {
      FUN_80006824(param_9,SFXfox_treadwater322);
    }
    else {
      FUN_80006824(param_9,SFXfoot_metal_run_2);
    }
    FUN_80006824(param_9,SFXdoor_unlocked);
    FUN_80006824(param_9,SFXkr_panting2);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
  }
  if (((*(byte *)(param_10 + 0x356) & 2) == 0) && (lbl_803E39C4 < ((GameObject *)param_9)->anim.currentMoveProgress)) {
    FUN_80006824(param_9,SFXdoor_creak);
    *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 2;
    (**(code **)(*DAT_803dd738 + 0x4c))(param_9,(int)*(short *)(iVar3 + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c1b4
 * EN v1.0 Address: 0x8015C1B4
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8015BFAC
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c1b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 10;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(byte *)(iVar2 + 0x406) < 0x33) {
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
  }
  else if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 0xc;
  fVar1 = lbl_803E39AC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  *(float *)(param_10 + 0x284) = fVar1;
  if ((*(byte *)(iVar2 + 0x404) & 2) == 0) {
    *(float *)(param_10 + 0x280) = lbl_803E39C8 + ((GameObject *)param_9)->anim.currentMoveProgress;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c3b4
 * EN v1.0 Address: 0x8015C3B4
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8015C0C4
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c3b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(undefined2 *)(iVar1 + 0x402) = 3;
    }
  }
  else {
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(iVar1 + 0x402) = 2;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) = lbl_803E39CC;
  }
  iVar1 = *(int *)(iVar1 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  *(undefined4 *)(param_10 + 0x280) = *(undefined4 *)(param_9 + 0x98);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c514
 * EN v1.0 Address: 0x8015C514
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8015C1D8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c514(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80017a98();
    iVar1 = FUN_80017a98();
    if (*(short *)(iVar1 + 0x46) == 0) {
      FUN_80006824(param_9,SFXfox_treadwater322);
    }
    else {
      FUN_80006824(param_9,SFXfoot_metal_run_2);
    }
    FUN_80006824(param_9,SFXkr_panting1);
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39CC;
  *(float *)(param_10 + 0x280) = lbl_803E39AC;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c654
 * EN v1.0 Address: 0x8015C654
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x8015C2B4
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    iVar1 = *(int *)(iVar2 + 0x40c);
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & ~1;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 2;
    FUN_80006824(param_9,SFXsc_fox_commdown);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateOpenState(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 timeDelta;
  extern f32 lbl_803E2D14;
  extern f32 lbl_803E2D70;
  extern f32 lbl_803E2D74;
  extern f32 lbl_803E2D78;
  GroundBaddieState *sub;
  int sub_40c;
  int p54;

  sub = ((GameObject *)obj)->extra;
  sub_40c = *(int *)&sub->control;
  p54 = *(int *)&((GameObject *)obj)->anim.hitReactState;
  *(s16 *)(p54 + 0x60) |= 1;
  ((GroundBaddieState *)p)->baddie.unk25F = 1;
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 11, lbl_803E2D14, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  if (*(char *)(p + 0x27a) != '\0') {
    GameBit_Set(sub->gameBitB, 1);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    ((GameObject *)obj)->anim.alpha = 0xff;
    *(s8 *)(p + 0x34d) = 1;
    ((GroundBaddieState *)p)->baddie.moveSpeed = lbl_803E2D70 + (f32)(u32)sub->aggression / lbl_803E2D74;
  }
  if (*(s8 *)(p + 0x346) != 0) {
    sub->targetState = 1;
  }
  {
    int v = *(int *)(p + 0x314);
    if ((v & 0x200) != 0) {
      ((GroundBaddieState *)p)->baddie.eventFlags = v & ~0x200;
      *(u8 *)(sub_40c + 0x44) |= 0x20;
    }
  }
  *(u8 *)(sub_40c + 0x44) |= 0x4;
  if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E2D78) {
    *(u8 *)(sub_40c + 0x44) |= 0x8;
  }
  (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))(obj, p, timeDelta, 4);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateOpenHitState(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 timeDelta;
  extern f32 lbl_803E2D14;
  extern f32 lbl_803E2D78;
  extern f32 lbl_803E2D7C;
  extern f32 lbl_803E2D80;
  GroundBaddieState *sub;
  int sub_40c;
  int p54;

  sub = ((GameObject *)obj)->extra;
  sub_40c = *(int *)&sub->control;
  p54 = *(int *)&((GameObject *)obj)->anim.hitReactState;
  *(s16 *)(p54 + 0x60) |= 1;
  ((GroundBaddieState *)p)->baddie.unk25F = 1;
  p54 = *(int *)&((GameObject *)obj)->anim.hitReactState;
  *(u8 *)(p54 + 0x6e) = 9;
  p54 = *(int *)&((GameObject *)obj)->anim.hitReactState;
  *(u8 *)(p54 + 0x6f) = 1;
  ObjHits_RegisterActiveHitVolumeObject(obj);
  if (*(char *)(p + 0x27a) != '\0') {
    ObjAnim_SetCurrentMove(obj, 8, lbl_803E2D14, 0);
    *(s8 *)(p + 0x346) = 0;
  }
  if (*(char *)(p + 0x27a) != '\0') {
    GameBit_Set(sub->gameBitB, 1);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
    ((GameObject *)obj)->anim.alpha = 0xff;
    *(s8 *)(p + 0x34d) = 1;
    ((GroundBaddieState *)p)->baddie.moveSpeed = lbl_803E2D7C + (f32)(u32)sub->aggression / lbl_803E2D80;
  }
  if (*(s8 *)(p + 0x346) != 0) {
    sub->targetState = 1;
  }
  {
    int v = *(int *)(p + 0x314);
    if ((v & 0x200) != 0) {
      ((GroundBaddieState *)p)->baddie.eventFlags = v & ~0x200;
      *(u8 *)(sub_40c + 0x44) |= 0x20;
    }
  }
  *(u8 *)(sub_40c + 0x44) |= 0x4;
  if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E2D78) {
    *(u8 *)(sub_40c + 0x44) |= 0x8;
  }
  (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))(obj, p, timeDelta, 4);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8015c7a0
 * EN v1.0 Address: 0x8015C7A0
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x8015C3A0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c7a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015c8bc
 * EN v1.0 Address: 0x8015C8BC
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x8015C44C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015c8bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 0xc;
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xf,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
  }
  *(float *)(param_10 + 0x2a0) = *(float *)(param_10 + 0x2c0) / lbl_803E39D4;
  if (*(float *)(param_10 + 0x2a0) <= lbl_803E39D8) {
    if (*(float *)(param_10 + 0x2a0) < lbl_803E39D0) {
      *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
    }
  }
  else {
    *(float *)(param_10 + 0x2a0) = lbl_803E39D8;
  }
  fVar2 = ((GameObject *)param_9)->anim.currentMoveProgress;
  if (lbl_803E39BC <= fVar2) {
    *(float *)(param_10 + 0x280) = lbl_803E39DC * (lbl_803E39E0 - fVar2);
  }
  else {
    *(float *)(param_10 + 0x280) = lbl_803E39DC * fVar2;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015ca54
 * EN v1.0 Address: 0x8015CA54
 * EN v1.0 Size: 728b
 * EN v1.1 Address: 0x8015C560
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015ca54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 10;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = randomGetRange(0,2);
    lbl_803DDA79 = (undefined)uVar1;
    uVar1 = randomGetRange(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,3,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,7,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E39E4 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39E8;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else if ((*(float *)(param_10 + 0x2c0) <= lbl_803E39EC) || (*(char *)(param_10 + 0x346) != '\0')
          ) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else {
    *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
    *(float *)(param_10 + 0x280) =
         *(float *)(param_10 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39F0);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015cd2c
 * EN v1.0 Address: 0x8015CD2C
 * EN v1.0 Size: 736b
 * EN v1.1 Address: 0x8015C758
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015cd2c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar2 + 0x40c) + 0x44) | 4;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 10;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = randomGetRange(0,1);
    if (uVar1 == 0) {
      lbl_803DDA78 = 3;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,10,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      uVar1 = randomGetRange(0,2);
      lbl_803DDA78 = (undefined)uVar1;
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,6,0,param_12,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E39E4 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39E8;
  }
  if ((*(byte *)(iVar2 + 0x406) < 0x33) || ((*(byte *)(iVar2 + 0x404) & 2) != 0)) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else if ((*(float *)(param_10 + 0x2c0) <= lbl_803E39EC) || (*(char *)(param_10 + 0x346) != '\0')
          ) {
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  else {
    *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x2c0) / lbl_803E39EC - lbl_803E39E0;
    *(float *)(param_10 + 0x280) =
         *(float *)(param_10 + 0x280) *
         ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E39F0);
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d00c
 * EN v1.0 Address: 0x8015D00C
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x8015C958
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d00c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,9,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  iVar1 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    *(undefined2 *)(iVar2 + 0x402) = 4;
  }
  *param_9 = (short)(int)(lbl_803E39F4 *
                          (((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_10 + 0x336) ^ 0x80000000)
                                   - DOUBLE_803e3a00) * lbl_803DC074) / lbl_803E39F8) +
                         (float)((double)CONCAT44(0x43300000,(int)*param_9 ^ 0x80000000) -
                                DOUBLE_803e3a00));
  *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
  *(float *)(param_10 + 0x280) = lbl_803E39E0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d19c
 * EN v1.0 Address: 0x8015D19C
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8015CA70
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d19c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 10;
  ((ObjHitsPriorityState *)*(int *)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,4,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 3;
  *(float *)(param_10 + 0x2a0) = lbl_803E39C0;
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x10;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0xc;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d324
 * EN v1.0 Address: 0x8015D324
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x8015CB60
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d324(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)&((GameObject *)param_9)->extra;
  if ((*(short *)(param_10 + 0x276) != 4) && (*(char *)(param_10 + 0x27a) != '\0')) {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xe,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) = *(byte *)(*(int *)(iVar1 + 0x40c) + 0x44) | 0xc;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->flags &= ~1;
    *(float *)(param_10 + 0x2a0) = lbl_803E39D0;
    *(float *)(param_10 + 0x280) = lbl_803E39AC;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    GameBit_Set((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    *(undefined2 *)(iVar1 + 0x402) = 0;
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode | 8;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d518
 * EN v1.0 Address: 0x8015D518
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x8015CC74
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d518(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  iVar1 = *(int *)(iVar2 + 0x40c);
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->flags |= 1;
  *(undefined *)(param_10 + 0x25f) = 1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xb,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    GameBit_Set((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode & 0xf7;
    ((GameObject *)param_9)->anim.alpha = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E3A08 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E3A0C;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x20;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (((GameObject *)param_9)->anim.currentMoveProgress < lbl_803E3A10) {
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 8;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d6ec
 * EN v1.0 Address: 0x8015D6EC
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x8015CE08
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015d6ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  iVar1 = *(int *)(iVar2 + 0x40c);
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->flags |= 1;
  *(undefined *)(param_10 + 0x25f) = 1;
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->hitVolumePriority = 9;
  (*(ObjHitsPriorityState **)&((GameObject *)param_9)->anim.hitReactState)->hitVolumeId = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E39AC,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,8,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    GameBit_Set((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode = *(byte *)&((GameObject *)param_9)->anim.resetHitboxMode & 0xf7;
    ((GameObject *)param_9)->anim.alpha = 0xff;
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E3A14 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e39a0) /
         lbl_803E3A18;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
  }
  if ((*(uint *)(param_10 + 0x314) & 0x200) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 0x20;
  }
  *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 4;
  if (((GameObject *)param_9)->anim.currentMoveProgress < lbl_803E3A10) {
    *(byte *)(iVar1 + 0x44) = *(byte *)(iVar1 + 0x44) | 8;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_9,param_10,4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8015d91c
 * EN v1.0 Address: 0x8015D91C
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x8015CFB8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015d91c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_80017aa4(0x24,100);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_10 + 0x14);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_10 + 0x18);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_10 + 0x1c);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 1;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar3 != 0) {
      *(undefined4 *)(iVar3 + 0x24) = *(undefined4 *)(param_10 + 0x38);
      *(undefined4 *)(iVar3 + 0x28) = *(undefined4 *)(param_10 + 0x3c);
      *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(param_10 + 0x40);
      *(undefined4 *)(iVar3 + 0xc4) = param_9;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015da7c
 * EN v1.0 Address: 0x8015DA7C
 * EN v1.0 Size: 964b
 * EN v1.1 Address: 0x8015D07C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015da7c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  fVar1 = lbl_803E39E0;
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar7 = *(int *)(iVar5 + 0x40c);
  if (*(short *)(iVar2 + 0x46) == 99) {
    *(float *)(iVar7 + 0x28) = lbl_803E3A1C;
    fVar1 = lbl_803E3A20;
  }
  else {
    *(float *)(iVar7 + 0x28) = lbl_803E39E0;
  }
  dVar8 = (double)fVar1;
  uVar3 = 0;
  if ((*(char *)(iVar5 + 0x25f) != '\0') &&
     (uVar3 = (uint)(byte)(&DAT_80320a98)[*(char *)(iVar5 + 0xbc)], 0x1e < uVar3)) {
    uVar3 = 0;
  }
  puVar6 = &DAT_80320a88 + uVar3 * 3;
  if ((*(byte *)(iVar7 + 0x44) & 1) != 0) {
    FUN_8015d91c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,iVar7);
    *(byte *)(iVar7 + 0x44) = *(byte *)(iVar7 + 0x44) & 0xfe;
  }
  if (((*(byte *)(iVar7 + 0x44) & 4) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    iVar4 = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)iVar2, 0x56, (void *)(iVar7 + 0x20),
                                       0x200001, -1, puVar6);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 4);
  }
  if (((*(byte *)(iVar7 + 0x44) & 8) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    (*gPartfxInterface)->spawnObject((void *)iVar2, 0x57, (void *)(iVar7 + 0x20),
                                     0x200001, -1, puVar6);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x10) != 0) {
    FUN_800069bc();
    FUN_80006920((double)(float)((double)lbl_803E3A20 * dVar8));
    iVar5 = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)iVar2, 0x57, (void *)(iVar7 + 0x20),
                                       0x200001, -1, puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x20) != 0) {
    FUN_800069bc();
    FUN_80006920((double)(float)((double)lbl_803E3A24 * dVar8));
    iVar5 = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)iVar2, 0x57, (void *)(iVar7 + 0x20),
                                       0x200001, -1, puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
    iVar5 = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)iVar2, 0x58, (void *)(iVar7 + 0x20),
                                       0x200001, -1, puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 10);
  }
  *(undefined *)(iVar7 + 0x44) = 0;
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015de40
 * EN v1.0 Address: 0x8015DE40
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x8015D314
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015de40(short *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_98;
  float local_94;
  float local_90;
  undefined auStack_8c [12];
  float local_80;
  float local_7c;
  float local_78;
  float afStack_74 [12];
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar3 = *(int *)(param_2 + 0x40c);
  uVar2 = ObjPath_GetPointModelMtx((int)param_1,1);
  FUN_80003494((uint)afStack_74,uVar2,0x40);
  local_3c = lbl_803E39AC;
  local_40 = lbl_803E39AC;
  local_44 = lbl_803E39AC;
  fVar1 = lbl_803E39C4;
  if (param_1[0x23] == 99) {
    fVar1 = lbl_803E39E0;
  }
  dVar4 = (double)*(float *)(param_2 + 0x280);
  if (dVar4 < (double)fVar1) {
    dVar4 = (double)fVar1;
  }
  if (*(short *)(param_2 + 0x274) == 4) {
    ObjPath_GetPointWorldPosition(param_1,0,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  else {
    ObjPath_GetPointWorldPosition(param_1,2,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  *(float *)(iVar3 + 0x30) = lbl_803E3A28 + *(float *)(param_1 + 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_80293f90();
  *(float *)(iVar3 + 0x2c) =
       -(float)(dVar4 * (double)(float)((double)lbl_803E3A2C * dVar5) -
               (double)*(float *)(iVar3 + 0x2c));
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(iVar3 + 0x34) =
       -(float)(dVar4 * (double)(float)((double)lbl_803E3A2C * dVar5) -
               (double)*(float *)(iVar3 + 0x34));
  local_80 = lbl_803E39AC;
  local_7c = lbl_803E3A38;
  local_78 = lbl_803E3A3C;
  ObjPath_GetPointWorldPosition(param_1,0,&local_80,&local_7c,&local_78,1);
  if ((*(byte *)(iVar3 + 0x44) & 2) != 0) {
    local_98 = lbl_803E3A40;
    local_94 = lbl_803E3A44;
    local_90 = lbl_803E3A3C;
    FUN_80017778((double)lbl_803E3A40,(double)lbl_803E3A44,(double)lbl_803E3A3C,afStack_74,
                 &local_98,&local_94,&local_90);
    FUN_80003494(iVar3 + 0x38,(uint)&local_98,0xc);
    FUN_80003494(iVar3 + 8,(uint)auStack_8c,0x18);
    *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e038
 * EN v1.0 Address: 0x8015E038
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x8015D544
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015e038(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  
  ObjHits_DisableObject(param_1);
  if ((((GroundBaddieState *)param_2)->configFlags & 4) == 0) {
    if ((((GroundBaddieState *)param_2)->configFlags & 8) == 0) {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(float)((double)CONCAT44(0x43300000,
                                                          (uint)((GroundBaddieState *)param_2)->aggroRange) -
                                        DOUBLE_803e39a0),param_1,param_3,0x8000);
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(lbl_803E39BC *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)((GroundBaddieState *)param_2)->aggroRange) -
                                        DOUBLE_803e39a0)),param_1,param_3,0x8000);
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd738 + 0x48))((double)lbl_803E39EC,param_1,param_3,0x8000);
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd70c + 0x30))((double)lbl_803DC074,param_1,param_3,4);
    uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)lbl_803E3998,param_1,param_3);
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd738 + 0x28))
              (param_1,param_3,param_2 + 0x35c,(int)((GroundBaddieState *)param_2)->gameBitB,0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar1;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(param_2 + 0x402) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015e21c
 * EN v1.0 Address: 0x8015E21C
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8015D728
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015e21c(uint param_1,int param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0x40c);
  *(ushort *)(iVar2 + 0x46) = *(short *)(iVar2 + 0x46) + (ushort)DAT_803dc070;
  if (299 < *(ushort *)(iVar2 + 0x46)) {
    uVar1 = randomGetRange(0,200);
    *(short *)(iVar2 + 0x46) = (short)uVar1;
    if ((*(short *)(param_3 + 0x274) == 7) || (*(short *)(param_3 + 0x274) == 8)) {
      FUN_80006824(param_1,SFXkr_jump2);
    }
  }
  if ((*(byte *)(param_2 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E3A48,param_1,param_3,0xffffffff);
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)lbl_803E39AC,param_1,param_3,0xffffffff);
  }
  *(undefined4 *)(param_2 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
  *(undefined4 *)(param_1 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)lbl_803DC074,(double)lbl_803DC074,param_1,param_3,&DAT_803ad1a8,
             &DAT_803ad188);
  *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_2 + 0x3e0);
  return;
}

extern f32 lbl_803E2CD8;
extern f32 lbl_803E2D00;
extern f32 lbl_803E2D14;
extern f32 lbl_803E2D10;
extern f32 lbl_803E2D18;
extern f32 lbl_803E2D1C;
extern f32 lbl_803E2D20;
extern f32 lbl_803E2D24;
extern f32 lbl_803E2D28;
extern f32 lbl_803E2D2C;
extern f32 lbl_803E2D30;
extern f32 lbl_803E2D34;
extern f32 lbl_803E2D38;
extern f32 lbl_803E2D3C;
extern f32 lbl_803E2D40;
extern f32 lbl_803E2D44;
extern f32 lbl_803E2D48;
extern f32 lbl_803E2D4C;
extern f32 lbl_803E2D50;
extern f32 lbl_803E2D54;
extern f32 lbl_803E2D58;
extern f32 lbl_803E2D5C;
extern f32 lbl_803E2D60;
extern f32 lbl_803E2D84;
extern f32 lbl_803E2D88;
extern f32 lbl_803E2D8C;
extern f32 lbl_803E2D90;
extern f32 lbl_803E2D94;
extern f32 lbl_803E2D98;
extern f32 lbl_803E2D9C;
extern f32 lbl_803E2DA0;
extern f32 lbl_803E2DA4;
extern f32 lbl_803E2DA8;
extern f32 lbl_803E2DAC;
extern f32 lbl_803E2DB0;
extern f32 lbl_803E2DB4;
extern f32 timeDelta;
extern u8 framesThisStep;
extern int* gPlayerInterface;
extern int *gBaddieControlInterface;
extern f32 lbl_803E2CE8;
extern f32 lbl_803E2CEC;
extern f32 lbl_803E2CF0;
extern f32 lbl_803E2CF4;
extern f32 lbl_803E2CF8;
extern f32 lbl_803E2CFC;
extern int* Obj_GetActiveModel(int* obj);
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void renderWhirlpool(void);
extern void Camera_DisableViewYOffset(void);
extern void Obj_FreeObject(int obj);
extern void fn_8003B5E0(int arg0, int arg1, int arg2, int arg3);
extern void objRenderFn_8003b8f4(int obj, int arg1, int arg2, int arg3, int arg4, f32 scale);
extern void fn_8015CE68(int obj, int state);
extern u8 gMediumBasketStateHandlersA[];
extern u8 gMediumBasketStateHandlersB[];
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 sqrtf(f32 value);
extern u8 lbl_8031FDA0[];
extern u8 lbl_8031FE18[];
extern s16 lbl_8031FD80[];
extern s16 lbl_8031FD90[];
extern u8 lbl_8031FE38[];
extern u8 lbl_8031FE48[];
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern void *memcpy(void *dst, const void *src, u32 size);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);
extern void Matrix_TransformPoint(void *mtx, f32 *x, f32 *y, f32 *z);
extern void voxmaps_updateRoutePath(void *from, void *to);
void mediumbasket_spawnContactObject(int *obj, int *state);

#pragma scheduling off
void dll_CA_func0B(int obj, int message)
{
    GroundBaddieState *state = ((GameObject *)obj)->extra;

    switch ((u8)message) {
    case 0x80:
        ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, (int)state, 2);
        state->baddie.unk270 = 4;
        state->baddie.moveJustStartedB = 1;
        break;
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerB04(int obj, int state)
{
    if ((s8)*(u8 *)(state + 0x27b) != 0) {
        ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 2);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerB03(int obj, int state)
{
    GroundBaddieState *sub;

    if ((s8)*(u8 *)(state + 0x27b) != 0) {
        sub = ((GameObject *)obj)->extra;
        sub->unk405 = 0;
        GameBit_Set((s32)sub->gameBitB, 0);
        GameBit_Set((s32)sub->gameBitA, 1);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerB02(int obj, int state)
{
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedB != 0) {
        ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 0xd);
        *(int *)(state + 0x2d0) = 0;
        ((GroundBaddieState *)state)->baddie.unk25F = 0;
        ((GroundBaddieState *)state)->baddie.unk349 = 0;
        ObjHits_DisableObject(obj);
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else if ((s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, obj);
        if (((GameObject *)obj)->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateLandingState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int player;
    f32 noBlend;

    ((GroundBaddieState *)state)->baddie.unk34D = 3;
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D28;
    noBlend = lbl_803E2D14;
    ((GroundBaddieState *)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState *)state)->baddie.animSpeedB = noBlend;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 1, noBlend, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    if ((((GroundBaddieState *)state)->baddie.unk356 & 1) == 0) {
        player = Obj_GetPlayerObject();
        if (*(s16 *)(player + 0x46) == 0) goto playGroundLandSound;
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        goto playLandingExtras;
playGroundLandSound:
        Sfx_PlayFromObject(obj, SFXfox_treadwater322);
playLandingExtras:
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXkr_panting2);
        ((GroundBaddieState *)state)->baddie.unk356 |= 1;
    }
    if ((((GroundBaddieState *)state)->baddie.unk356 & 2) == 0 && ((GameObject *)obj)->anim.currentMoveProgress > lbl_803E2D2C) {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        ((GroundBaddieState *)state)->baddie.unk356 |= 2;
        ((void (*)(int, int, int, int))((void **)*gBaddieControlInterface)[19])(
            obj, (s32)sub->unk3F0, -1, 0);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateContactHitState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int control;
    f32 noBlend;

    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (sub->aggression > 0x32) {
        if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E2D14, 0);
            ((GroundBaddieState *)state)->baddie.moveDone = 0;
        }
    } else if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState *)state)->baddie.unk34D = 3;
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D28;
    control = *(int *)&sub->control;
    *(u8 *)(control + 0x44) |= 0xc;
    noBlend = lbl_803E2D14;
    ((GroundBaddieState *)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState *)state)->baddie.animSpeedB = noBlend;
    if ((sub->configFlags & 2) == 0) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D30 + ((GameObject *)obj)->anim.currentMoveProgress;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerA0B(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int control;

    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA == 0) {
        if ((s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
            sub->targetState = 3;
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        ObjAnim_SetCurrentMove(obj, 2, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
        sub->targetState = 2;
        ((GroundBaddieState *)state)->baddie.unk34D = 1;
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D34;
    }
    control = *(int *)&sub->control;
    *(u8 *)(control + 0x44) |= 4;
    if ((s32)(((GroundBaddieState *)state)->baddie.eventFlags & 0x200) != 0) {
        ((GroundBaddieState *)state)->baddie.eventFlags &= ~0x200;
        *(u8 *)(control + 0x44) |= 0x10;
    }
    *(u8 *)(control + 0x44) |= 0xc;
    ((GroundBaddieState *)state)->baddie.animSpeedA = ((GameObject *)obj)->anim.currentMoveProgress;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateDropState(int obj, int state)
{
    int control = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
    int player;

    *(u8 *)(control + 0x44) |= 4;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        Obj_GetPlayerObject();
        player = Obj_GetPlayerObject();
        if (*(s16 *)(player + 0x46) == 0) goto playGroundDropSound;
        Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        goto playDropExtras;
playGroundDropSound:
        Sfx_PlayFromObject(obj, SFXfox_treadwater322);
playDropExtras:
        Sfx_PlayFromObject(obj, SFXkr_panting1);
    }
    ((GroundBaddieState *)state)->baddie.unk34D = 3;
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D34;
    ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateCommDownState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int control = *(int *)&sub->control;

    *(u8 *)(control + 0x44) |= 4;
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D38;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 10, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState *)state)->baddie.unk34D = 1;
    if ((*(s32 *)(state + 0x314) & 1) != 0) {
        control = *(int *)&sub->control;
        ((GroundBaddieState *)state)->baddie.eventFlags &= ~1;
        *(u8 *)(control + 0x44) |= 2;
        Sfx_PlayFromObject(obj, SFXsc_fox_commdown);
    }
    ((void (*)(int, int, f32, int))((void **)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateHeightBlendState(int obj, int state)
{
    int control = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
    f32 height;

    *(u8 *)(control + 0x44) |= 0xc;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0xf, lbl_803E2D14, 0);
            ((GroundBaddieState *)state)->baddie.moveDone = 0;
        }
        ((GroundBaddieState *)state)->baddie.unk34D = 1;
    }
    ((GroundBaddieState *)state)->baddie.moveSpeed = ((GroundBaddieState *)state)->baddie.targetDistance / lbl_803E2D3C;
    if (((GroundBaddieState *)state)->baddie.moveSpeed > lbl_803E2D40) {
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D40;
    } else if (((GroundBaddieState *)state)->baddie.moveSpeed < lbl_803E2D38) {
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D38;
    }
    height = ((GameObject *)obj)->anim.currentMoveProgress;
    if (height < lbl_803E2D24) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D44 * height;
    } else {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D44 * (lbl_803E2D48 - height);
    }
    ((void (*)(int, int, f32, int))((void **)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerA06(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int choice;

    *(u8 *)(*(int *)&sub->control + 0x44) |= 4;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        lbl_803DDA79 = randomGetRange(0, 2);
        choice = randomGetRange(0, 1);
        if (choice == 0) {
            if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 3, lbl_803E2D14, 0);
                ((GroundBaddieState *)state)->baddie.moveDone = 0;
            }
        } else {
            if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 7, lbl_803E2D14, 0);
                ((GroundBaddieState *)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState *)state)->baddie.unk34D = 1;
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D4C + (f32)sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression <= 50 || (sub->configFlags & 2) != 0) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    } else if (((GroundBaddieState *)state)->baddie.targetDistance <= lbl_803E2D54 || (s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    } else {
        ((GroundBaddieState *)state)->baddie.animSpeedA = ((GroundBaddieState *)state)->baddie.targetDistance / lbl_803E2D54 - lbl_803E2D48;
        ((GroundBaddieState *)state)->baddie.animSpeedA =
            ((GroundBaddieState *)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
    }
    ((void (*)(int, int, f32, int))((void **)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerA05(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int choice;

    *(u8 *)(*(int *)&sub->control + 0x44) |= 4;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        choice = randomGetRange(0, 1);
        if (choice == 0) {
            lbl_803DDA78 = 3;
            if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E2D14, 0);
                ((GroundBaddieState *)state)->baddie.moveDone = 0;
            }
        } else {
            lbl_803DDA78 = randomGetRange(0, 2);
            if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 6, lbl_803E2D14, 0);
                ((GroundBaddieState *)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState *)state)->baddie.unk34D = 1;
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D4C + (f32)sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression <= 50 || (sub->configFlags & 2) != 0) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    } else if (((GroundBaddieState *)state)->baddie.targetDistance <= lbl_803E2D54 || (s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    } else {
        ((GroundBaddieState *)state)->baddie.animSpeedA = ((GroundBaddieState *)state)->baddie.targetDistance / lbl_803E2D54 - lbl_803E2D48;
        ((GroundBaddieState *)state)->baddie.animSpeedA =
            ((GroundBaddieState *)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
    }
    ((void (*)(int, int, f32, int))((void **)*gPlayerInterface)[12])(obj, state, timeDelta, 4);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateSpinState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int control;

    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 9, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    control = *(int *)&sub->control;
    *(u8 *)(control + 0x44) |= 0xc;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        sub->targetState = 4;
    }
    *(s16 *)obj = (s16)(lbl_803E2D5C *
                        (((f32)((GroundBaddieState *)state)->baddie.unk336 * timeDelta) / lbl_803E2D60) +
                        (f32)*(s16 *)obj);
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D38;
    ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D48;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateImpactHitState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int control = *(int *)&sub->control;

    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState *)*(int *)&((GameObject *)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 4, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState *)state)->baddie.unk34D = 3;
    ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D28;
    if ((s32)(((GroundBaddieState *)state)->baddie.eventFlags & 0x200) != 0) {
        ((GroundBaddieState *)state)->baddie.eventFlags &= ~0x200;
        *(u8 *)(control + 0x44) |= 0x10;
    }
    *(u8 *)(control + 0x44) |= 0xc;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_updateHideResetState(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int hitState;

    if (((GroundBaddieState *)state)->baddie.unk276 != 4 && (s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState *)state)->baddie.moveDone = 0;
    }
    *(u8 *)(*(int *)&sub->control + 0x44) |= 0xc;
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedA != 0) {
        hitState = *(int *)&((GameObject *)obj)->anim.hitReactState;
        *(s16 *)(hitState + 0x60) &= ~1;
        ((GroundBaddieState *)state)->baddie.moveSpeed = lbl_803E2D38;
        ((GroundBaddieState *)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    if ((s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
        GameBit_Set((s32)sub->gameBitB, 0);
        ObjAnim_SetCurrentMove(obj, 8, lbl_803E2D14, 0);
        *(int *)(state + 0x2d0) = 0;
        ((GroundBaddieState *)state)->baddie.unk25F = 0;
        ((GroundBaddieState *)state)->baddie.unk349 = 0;
        sub->targetState = 0;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerB06(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;
    int route;
    f32 neutralBlend;

    if ((s8)((GroundBaddieState *)state)->baddie.moveDone != 0 &&
        (((u8)((int (*)(int, int, f32))((void **)*gBaddieControlInterface)[6])(
              obj, state, lbl_803E2D00) & 1) == 0)) {
        return 5;
    }
    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedB != 0) {
        ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 0xb);
    } else if (sub->targetState == 3) {
        ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 4);
    } else if (sub->targetState == 4) {
        if (((GroundBaddieState *)state)->baddie.targetDistance < lbl_803E2D10 && (s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
            if (sub->aggression > 50) {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 0);
            } else {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 1);
            }
        }
    } else if (sub->targetState == 1) {
        return 8;
    }
    route = (int)sub->route35C;
    neutralBlend = lbl_803E2D14;
    ((GroundBaddieState *)state)->baddie.unk290 = neutralBlend;
    ((GroundBaddieState *)state)->baddie.unk28C = neutralBlend;
    memcpy((void *)route, (void *)&((GameObject *)obj)->anim.localPosX, 0xc);
    memcpy((void *)(sub->route35C + 0xc), (void *)(*(int *)(state + 0x2d0) + 0xc), 0xc);
    voxmaps_updateRoutePath((void *)route, (void *)(sub->route35C + 0x28));
    if (*(u8 *)(route + 0x25) == 0) {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void **)*gPlayerInterface)[7])(
            obj, state, *(f32 *)(route + 0x18), *(f32 *)(route + 0x20), lbl_803E2D14,
            lbl_803E2D14, lbl_803E2D18);
    } else {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void **)*gPlayerInterface)[7])(
            obj, state, *(f32 *)(route + 0x18), *(f32 *)(route + 0x20), lbl_803E2D1C,
            lbl_803E2D20, lbl_803E2D18);
    }
    if (((GroundBaddieState *)state)->baddie.unk32E > 0x78 &&
        ((int (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[17])(
            obj, state, (f32)sub->aggroRange, 1) != 0) {
        return 5;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mediumbasket_stateHandlerB07(int obj, int state)
{
    GroundBaddieState *sub = ((GameObject *)obj)->extra;

    if ((s8)((GroundBaddieState *)state)->baddie.moveJustStartedB != 0) {
        if ((s32)((GroundBaddieState *)state)->baddie.targetDistance > 0x37) {
            if ((sub->configFlags & 2) == 0) {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 7);
            } else {
                int control = *(int *)&sub->control;
                if ((sub->configFlags & 0x10) != 0) {
                    int attackIndex = *(s16 *)(control + 4);
                    *(u16 *)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD90[attackIndex]);
                } else {
                    int attackIndex = *(s16 *)(control + 4);
                    *(u16 *)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD80[attackIndex]);
                }
                if (*(s16 *)(control + 4) >= 7) {
                    *(s16 *)(control + 4) = 0;
                }
            }
        } else {
            if (((GroundBaddieState *)state)->baddie.controlMode == 6) {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 5);
            } else {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    } else if ((s8)((GroundBaddieState *)state)->baddie.moveDone != 0) {
        if ((((u8)((int (*)(int, int, f32))((void **)*gBaddieControlInterface)[6])(
                  obj, state, lbl_803E2D00) & 1) == 0)) {
            return 5;
        }
        if (((int (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[17])(
                obj, state, (f32)sub->aggroRange, 1) != 0) {
            return 5;
        }
        if ((s32)((GroundBaddieState *)state)->baddie.targetDistance > 0x37) {
            if ((sub->configFlags & 2) == 0) {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 7);
            } else {
                int control = *(int *)&sub->control;
                if ((sub->configFlags & 0x10) != 0) {
                    int attackIndex = *(s16 *)(control + 4);
                    *(u16 *)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD90[attackIndex]);
                } else {
                    int attackIndex = *(s16 *)(control + 4);
                    *(u16 *)(control + 4) = attackIndex + 1;
                    ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(
                        obj, state, (s32)lbl_8031FD80[attackIndex]);
                }
                if (*(s16 *)(control + 4) >= 7) {
                    *(s16 *)(control + 4) = 0;
                }
            }
        } else {
            if (((GroundBaddieState *)state)->baddie.controlMode == 6) {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 5);
            } else {
                ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    } else if (((GroundBaddieState *)state)->baddie.controlMode == 7 && (s32)((GroundBaddieState *)state)->baddie.targetDistance < 0x37) {
        if (((GroundBaddieState *)state)->baddie.controlMode == 6) {
            ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 5);
        } else {
            ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 6);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8015CE68(int obj, int state)
{
    int control = *(int *)(state + 0x40c);
    f32 transformedX;
    f32 transformedY;
    f32 transformedZ;
    u8 transformScratch[0x18];
    f32 pathX;
    f32 pathY;
    f32 pathZ;
    f32 pathMtx[16];
    f32 scale;
    f32 angle;

    memcpy(pathMtx, (void *)ObjPath_GetPointModelMtx(obj, 1), 0x40);
    pathMtx[14] = lbl_803E2D14;
    pathMtx[13] = lbl_803E2D14;
    pathMtx[12] = lbl_803E2D14;
    if (((GameObject *)obj)->anim.seqId == 99) {
        scale = lbl_803E2D48;
    } else {
        scale = lbl_803E2D2C;
    }
    if (*(f32 *)(state + 0x280) >= scale) {
        scale = *(f32 *)(state + 0x280);
    }
    if (*(s16 *)(state + 0x274) == 4) {
        ObjPath_GetPointWorldPosition(obj, 0, (f32 *)(control + 0x2c),
                                      (f32 *)(control + 0x30), (f32 *)(control + 0x34), 0);
    } else {
        ObjPath_GetPointWorldPosition(obj, 2, (f32 *)(control + 0x2c),
                                      (f32 *)(control + 0x30), (f32 *)(control + 0x34), 0);
    }
    *(f32 *)(control + 0x30) = lbl_803E2D90 + ((GameObject *)obj)->anim.localPosY;
    angle = (lbl_803E2D98 * (f32)*(s16 *)obj) / lbl_803E2D9C;
    *(f32 *)(control + 0x2c) =
        *(f32 *)(control + 0x2c) - scale * (lbl_803E2D94 * mathSinf(angle));
    angle = (lbl_803E2D98 * (f32)*(s16 *)obj) / lbl_803E2D9C;
    *(f32 *)(control + 0x34) =
        *(f32 *)(control + 0x34) - scale * (lbl_803E2D94 * mathCosf(angle));
    pathX = lbl_803E2D14;
    pathY = lbl_803E2DA0;
    pathZ = lbl_803E2DA4;
    ObjPath_GetPointWorldPosition(obj, 0, &pathX, &pathY, &pathZ, 1);
    if ((*(u8 *)(control + 0x44) & 2) != 0) {
        transformedX = lbl_803E2DA8;
        transformedY = lbl_803E2DAC;
        transformedZ = lbl_803E2DA4;
        Matrix_TransformPoint(pathMtx, &transformedX, &transformedY, &transformedZ);
        memcpy((void *)(control + 0x38), &transformedX, 0xc);
        memcpy((void *)(control + 8), transformScratch, 0x18);
        *(u8 *)(control + 0x44) |= 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mediumbasket_updateControlEffects(int obj, int state)
{
    int control = *(int *)(state + 0x40c);
    int paletteIndex;
    u8 *particleArgs;
    int i;
    f32 shakeScale;
    f32 contactScale;

    if (((GameObject *)obj)->anim.seqId == 99) {
        *(f32 *)(control + 0x28) = lbl_803E2D84;
        shakeScale = lbl_803E2D88;
    } else {
        contactScale = lbl_803E2D48;
        *(f32 *)(control + 0x28) = contactScale;
        shakeScale = contactScale;
    }
    paletteIndex = 0;
    if ((s8)((GroundBaddieState *)state)->baddie.unk25F != 0) {
        paletteIndex = lbl_8031FE48[(s8)((GroundBaddieState *)state)->baddie.unkBC];
        if (paletteIndex > 0x1e) {
            paletteIndex = 0;
        }
    }
    particleArgs = &lbl_8031FE38[paletteIndex * 3];
    if ((*(u8 *)(control + 0x44) & 1) != 0) {
        mediumbasket_spawnContactObject((int *)obj, (int *)control);
        *(u8 *)(control + 0x44) &= ~1;
    }
    if ((*(u8 *)(control + 0x44) & 4) != 0 && (((GroundBaddieState *)state)->configFlags & 0x40) == 0) {
        for (i = 0; i < 4; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x56, (void *)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    if ((*(u8 *)(control + 0x44) & 8) != 0 && (((GroundBaddieState *)state)->configFlags & 0x40) == 0) {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x57, (void *)(control + 0x20), 0x200001, -1, particleArgs);
    }
    if ((*(u8 *)(control + 0x44) & 0x10) != 0) {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D88 * shakeScale);
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x57, (void *)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    if ((*(u8 *)(control + 0x44) & 0x20) != 0) {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D8C * shakeScale);
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x57, (void *)(control + 0x20), 0x200001, -1, particleArgs);
        }
        for (i = 0; i < 10; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x58, (void *)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    *(u8 *)(control + 0x44) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mediumbasket_updateTargetMotion(int obj, int sub, int state)
{
    int control = *(int *)(sub + 0x40c);

    *(u16 *)(control + 0x46) += framesThisStep;
    if (*(u16 *)(control + 0x46) >= 300) {
        *(u16 *)(control + 0x46) = randomGetRange(0, 200);
        if (*(s16 *)(state + 0x274) == 7 || *(s16 *)(state + 0x274) == 8) {
            Sfx_PlayFromObject(obj, SFXkr_jump2);
        }
    }
    if ((*(u8 *)(sub + 0x404) & 2) != 0) {
        ((void (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[11])(
            obj, state, lbl_803E2D14, -1);
    } else {
        ((void (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[11])(
            obj, state, lbl_803E2DB0, -1);
    }
    *(int *)(sub + 0x3e0) = *(int *)&((GameObject *)obj)->unkC0;
    *(int *)&((GameObject *)obj)->unkC0 = 0;
    ((void (*)(int, int, f32, f32, u8 *, u8 *))((void **)*gPlayerInterface)[2])(
        obj, state, timeDelta, timeDelta, gMediumBasketStateHandlersA, gMediumBasketStateHandlersB);
    *(int *)&((GameObject *)obj)->unkC0 = *(int *)(sub + 0x3e0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma fp_contract off
void fn_8015D3C0(int obj, int sub, int state)
{
    int control = *(int *)(sub + 0x40c);
    u8 *target;
    int hitInfo[7];
    f32 targetDelta[3];
    f32 distSq;

    Obj_GetPlayerObject();
    target = *(u8 **)(state + 0x2d0);
    if (target != NULL) {
        targetDelta[0] = ((GameObject *)target)->anim.worldPosX - ((GameObject *)obj)->anim.worldPosX;
        targetDelta[1] = ((GameObject *)target)->anim.worldPosY - ((GameObject *)obj)->anim.worldPosY;
        targetDelta[2] = ((GameObject *)target)->anim.worldPosZ - ((GameObject *)obj)->anim.worldPosZ;
        distSq = targetDelta[2] * targetDelta[2];
        distSq += targetDelta[0] * targetDelta[0];
        distSq += targetDelta[1] * targetDelta[1];
        ((GroundBaddieState *)state)->baddie.targetDistance = sqrtf(distSq);
    }
    if ((((GroundBaddieState *)sub)->configFlags & 0x20) == 0) {
        ((void (*)(int, int, int, int, int, int, int))((void **)*gBaddieControlInterface)[15])(
            obj, state, sub + 0x400, 2, 3, (s32)((GroundBaddieState *)sub)->unk3FC,
            (s32)((GroundBaddieState *)sub)->unk3FA);
    }
    ((void (*)(int, int, int, int, int, int, int, int))((void **)*gBaddieControlInterface)[21])(
        obj, state, sub + 0x35c, (s32)((GroundBaddieState *)sub)->gameBitB, 0, 0, 0, 8);
    *(f32 *)control += timeDelta;
    if (((GroundBaddieState *)state)->baddie.controlMode != 3 &&
        ((int (*)(int, int, int, int, u8 *, u8 *, int, int *))((void **)*gBaddieControlInterface)[20])(
            obj, state, sub + 0x35c, (s32)((GroundBaddieState *)sub)->gameBitB, lbl_8031FDA0,
            lbl_8031FE18, 1, hitInfo) != 0) {
        if (*(f32 *)control < lbl_803E2DB4) {
            *(s16 *)(control + 6) += 1;
        } else {
            *(s16 *)(control + 6) = 0;
        }
        *(f32 *)control = lbl_803E2D14;
        if ((s8)((GroundBaddieState *)state)->baddie.hitPoints > 0 && *(s16 *)(control + 6) >= 2) {
            ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, state, 3);
            *(s16 *)(control + 6) = 0;
            ((GroundBaddieState *)state)->baddie.unk270 = 5;
        }
    }
}
#pragma fp_contract reset
#pragma peephole reset
#pragma scheduling reset

/* Pattern wrappers. */
s16 dll_CA_setScale(int *obj) { return *(s16*)((char*)((int**)obj)[0xb8/4] + 0x274); }

/* 8b "li r3, N; blr" returners. */
int dll_CA_getExtraSize_ret_1112(void) { return 0x458; }
int dll_CA_getObjectTypeId(void) { return 0x49; }

#pragma scheduling off
#pragma peephole off
void dll_CA_free(int obj)
{
    GroundBaddieState *state = ((GameObject *)obj)->extra;

    Camera_DisableViewYOffset();
    ObjGroup_RemoveObject(obj, 3);
    if (((GameObject *)obj)->unkC8 != NULL) {
        Obj_FreeObject(*(int *)&((GameObject *)obj)->unkC8);
        *(int *)&((GameObject *)obj)->unkC8 = 0;
    }
    ((void (*)(int, int, int))((void **)*gBaddieControlInterface)[16])(obj, (int)state, 0x20);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dll_CA_render(int obj, int arg1, int arg2, int arg3, int arg4, s8 visible)
{
    GroundBaddieState *state = ((GameObject *)obj)->extra;

    if (visible == 0) {
        goto done;
    }
    if (((GameObject *)obj)->unkF4 != 0) {
        goto done;
    }
    if (state->targetState != 0) {
        goto render;
    }
    goto done;

render:
    if (state->unk3E8 != lbl_803E2D14) {
        fn_8003B5E0(0xc8, 0, 0, (int)state->unk3E8);
    }
    objRenderFn_8003b8f4(obj, arg1, arg2, arg3, arg4, lbl_803E2D48);
    fn_8015CE68(obj, (int)state);
done:;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void dll_CA_hitDetect(int obj)
{
    ((void (*)(int, int, u8 *))((void **)*gPlayerInterface)[3])(obj, *(int *)&((GameObject *)obj)->extra,
                                                               gMediumBasketStateHandlersA);
}
#pragma scheduling reset

#pragma scheduling off
void mediumbasket_initWhirlpoolState(int* obj, GroundBaddieState *state) {
    f32 fz;
    state->baddie.unk2AC = lbl_803E2CE8;
    *(char *)&state->baddie.inWhirlpoolGroup = (int)state->baddie.unk2A8;
    state->baddie.unk2A8 = lbl_803E2CEC;
    state->baddie.unk2E4 = 0x42001;
    state->baddie.unk308 = lbl_803E2CF0;
    state->baddie.unk300 = lbl_803E2CF4;
    state->baddie.unk304 = lbl_803E2CF8;
    state->baddie.unk320 = 0;
    fz = lbl_803E2CFC;
    *(f32 *)&state->baddie.eventFlags = fz;
    state->baddie.unk321 = 5;
    state->baddie.unk318 = fz;
    state->baddie.unk322 = 7;
    state->baddie.unk31C = fz;
    state->baddie.unk33A = 1;
    state->baddie.inWhirlpoolGroup = 0;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(obj), (void*)renderWhirlpool);
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);

void mediumbasket_spawnContactObject(int* obj, int* state) {
    void* alloc;
    int* new_obj;
    if ((u8)Obj_IsLoadingLocked() != 0) {
        alloc = Obj_AllocObjectSetup(36, 100);
        *(f32*)((char*)alloc + 8) = *(f32*)((char*)state + 20);
        *(f32*)((char*)alloc + 12) = *(f32*)((char*)state + 24);
        *(f32*)((char*)alloc + 16) = *(f32*)((char*)state + 28);
        *(u8*)((char*)alloc + 4) = 1;
        *(u8*)((char*)alloc + 5) = 1;
        *(u8*)((char*)alloc + 6) = 255;
        *(u8*)((char*)alloc + 7) = 255;
        *(s16*)((char*)alloc + 30) = -1;
        *(s16*)((char*)alloc + 32) = -1;
        new_obj = Obj_SetupObject(alloc, 5, -1, -1, (void*)0);
        if (new_obj != NULL) {
            *(f32*)((char*)new_obj + 0x24) = *(f32*)((char*)state + 56);
            *(f32*)((char*)new_obj + 0x28) = *(f32*)((char*)state + 60);
            *(f32*)((char*)new_obj + 0x2c) = *(f32*)((char*)state + 64);
            *(int**)((char*)new_obj + 0xc4) = obj;
        }
    }
}

int mediumbasket_updateControlMove5State(int* obj, GroundBaddieState *state) {
    u8* t = *(u8**)((char*)(*(int**)&((GameObject *)obj)->extra) + 0x40c);
    t[0x44] |= 4;
    state->baddie.moveSpeed = lbl_803E2D38;
    if ((s8)state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2D14, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.unk34D = 1;
    ((void(*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[12])(obj, (u8 *)state, timeDelta, 4);
    return 0;
}

int mediumbasket_stateHandlerB05(int* obj, GroundBaddieState *state) {
    if ((s8)state->baddie.moveJustStartedB != 0) {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 3);
    }
    if ((s8)state->baddie.moveDone != 0) {
        if (state->baddie.controlMode == 3) {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 0);
        } else {
            return 8;
        }
    }
    return 0;
}

int mediumbasket_stateHandlerB01(int* obj, GroundBaddieState *state) {
    GroundBaddieState* sub = ((GameObject *)obj)->extra;
    if ((s8)state->baddie.hitPoints < 1) return 3;
    if ((s8)state->baddie.moveDone != 0) {
        if (state->baddie.controlMode == 12) {
            if (sub->aggression > 50) {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 0);
            } else {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8 *)state, 1);
            }
        } else {
            return 8;
        }
    }
    return 0;
}

void mediumbasket_leaveWhirlpoolGroup(int* obj, GroundBaddieState *state) {
    if (state->baddie.inWhirlpoolGroup != 0) {
        ObjGroup_RemoveObject(obj, 80);
        state->baddie.inWhirlpoolGroup = 0;
    }
    *(u16*)obj = (float)(int)*(s16*)obj - lbl_803E2CD8 * timeDelta;
}

void mediumbasket_enterWhirlpoolGroup(int* obj, GroundBaddieState *state) {
    if (state->baddie.inWhirlpoolGroup == 0) {
        ObjGroup_AddObject(obj, 80);
        state->baddie.inWhirlpoolGroup = 1;
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    ((GameObject *)obj)->anim.rotX -= 256;
}

void mediumbasket_tryAcquireTarget(int obj, int p2, int p3)
{
  extern int *gBaddieControlInterface;
  extern int *gPlayerInterface;
  extern void ObjHits_DisableObject(int);
  extern f32 timeDelta;
  extern f32 lbl_803E2D00;
  extern f32 lbl_803E2D24;
  extern f32 lbl_803E2D54;
  uint r;

  ObjHits_DisableObject(obj);

  if ((((GroundBaddieState *)p2)->configFlags & 0x4) != 0) {
    r = (**(uint (**)(int, int, f32, int))((char *)(*gBaddieControlInterface) + 0x48))(
            obj, p3, lbl_803E2D54, 0x8000);
  } else if ((((GroundBaddieState *)p2)->configFlags & 0x8) != 0) {
    r = (**(uint (**)(int, int, f32, int))((char *)(*gBaddieControlInterface) + 0x48))(
            obj, p3, lbl_803E2D24 * (f32)(u32)((GroundBaddieState *)p2)->aggroRange, 0x8000);
  } else {
    r = (**(uint (**)(int, int, f32, int))((char *)(*gBaddieControlInterface) + 0x48))(
            obj, p3, (f32)(u32)((GroundBaddieState *)p2)->aggroRange, 0x8000);
  }

  if (r != 0) {
    (**(void (**)(int, int, f32, int))((char *)(*gPlayerInterface) + 0x30))(obj, p3, timeDelta, 4);
    if (((u8)(**(int (**)(int, int, f32))((char *)(*gBaddieControlInterface) + 0x18))(obj, p3, lbl_803E2D00) & 1) == 0) {
      r = 0;
    }
  }

  if (r != 0) {
    int v = -1;
    (**(void (**)(int, int, int, int, int, int, int, int, int))((char *)(*gBaddieControlInterface) + 0x28))(
        obj, p3, p2 + 0x35c, (s32)((GroundBaddieState *)p2)->gameBitB, 0, 0, 0, 8, v);
    *(int *)(p3 + 0x2d0) = r;
    *(u8 *)(p3 + 0x349) = 0;
    ((GroundBaddieState *)p2)->targetState = 1;
  }
}

int mediumbasket_checkTargetState(int obj, int p2)
{
  extern int *gPlayerInterface;
  extern int *gBaddieControlInterface;
  extern f32 timeDelta;
  extern f32 lbl_803E2D00;
  extern f32 lbl_803E2D14;
  extern f32 lbl_803E2D24;
  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  f32 neutralBlend;

  if (((GroundBaddieState *)p2)->baddie.targetObj == NULL) goto return0;

  if ((s32)(s8)((GroundBaddieState *)p2)->baddie.moveJustStartedB != 0) {
    neutralBlend = lbl_803E2D14;
    ((GroundBaddieState *)p2)->baddie.animSpeedB = neutralBlend;
    ((GroundBaddieState *)p2)->baddie.animSpeedA = neutralBlend;
    if ((u32)sub->aggression > 50) {
      if (((GroundBaddieState *)p2)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)sub->aggroRange
          || (sub->configFlags & 0x2) != 0) {
        (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 0);
      } else {
        (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 1);
      }
    } else {
      (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 1);
    }
  }

  if ((s32)(s8)((GroundBaddieState *)p2)->baddie.moveDone == 0) goto return0;

  (**(void (**)(int, int, f32, int))((char *)(*gPlayerInterface) + 0x30))(obj, p2, timeDelta, 4);
  if (((u8)(**(int (**)(int, int, f32))((char *)(*gBaddieControlInterface) + 0x18))(obj, p2, lbl_803E2D00) & 1) == 0) {
    return 5;
  }

  if (((GroundBaddieState *)p2)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)sub->aggroRange
      || (sub->configFlags & 0x2) != 0) {
    return 8;
  }
  return 7;

return0:
  return 0;
}
