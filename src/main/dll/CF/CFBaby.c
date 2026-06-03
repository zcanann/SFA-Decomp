#include "ghidra_import.h"
#include "main/mapEvent.h"
#include "main/dll/CF/CFBaby.h"

#define SFXen_rfall5_c 72
#define SFXmv_liftloop 158

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006ba8();
extern void* FUN_80017470();
extern undefined4 FUN_80017680();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800178b8();
extern undefined4 FUN_80017a48();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_80053c98();
extern int FUN_800575b4();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_80081108();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8011d9b4();
extern char FUN_8012e0e0();
extern int FUN_8012efc4();
extern undefined4 FUN_8013651c();
extern undefined4 FUN_8020a758();
extern undefined4 FUN_8020a75c();
extern undefined4 FUN_80247edc();
extern double SeekTwiceBeforeRead();
extern int FUN_80286834();
extern int FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern uint FUN_80294c04();
extern int FUN_80294dbc();
extern void *Obj_GetPlayerObject(void);
extern int fn_801871C8(int *obj);
extern int fn_8018728C(int obj, int unused, int events);

extern undefined4 DAT_803225e0;
extern undefined4 DAT_803225f0;
extern undefined4 DAT_80322678;
extern undefined4 DAT_8032267c;
extern undefined4 DAT_8032267d;
extern undefined4 DAT_8032267e;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e47d0;
extern f64 DOUBLE_803e47f8;
extern f64 DOUBLE_803e4818;
extern f64 DOUBLE_803e4828;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4738;
extern f32 FLOAT_803e4750;
extern f32 FLOAT_803e4770;
extern f32 FLOAT_803e4774;
extern f32 FLOAT_803e4778;
extern f32 FLOAT_803e4780;
extern f32 FLOAT_803e4784;
extern f32 FLOAT_803e4790;
extern f32 FLOAT_803e4794;
extern f32 FLOAT_803e4798;
extern f32 FLOAT_803e479c;
extern f32 FLOAT_803e47a0;
extern f32 FLOAT_803e47a4;
extern f32 FLOAT_803e47a8;
extern f32 FLOAT_803e47ac;
extern f32 FLOAT_803e47b0;
extern f32 FLOAT_803e47b8;
extern f32 FLOAT_803e47bc;
extern f32 FLOAT_803e47c0;
extern f32 FLOAT_803e47c4;
extern f32 FLOAT_803e47c8;
extern f32 FLOAT_803e47cc;
extern f32 FLOAT_803e47dc;
extern f32 FLOAT_803e47e0;
extern f32 FLOAT_803e47e8;
extern f32 FLOAT_803e47ec;
extern f32 FLOAT_803e47f0;
extern f32 FLOAT_803e47f4;
extern f32 FLOAT_803e4800;
extern f32 FLOAT_803e4804;
extern f32 FLOAT_803e4810;
extern f32 FLOAT_803e4814;
extern f32 FLOAT_803e4820;
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4834;
extern f32 FLOAT_803e4838;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

/*
 * --INFO--
 *
 * Function: FireFlyLantern_init
 * EN v1.0 Address: 0x80187524
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80187608
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FireFlyLantern_init(int obj, int def)
{
  void *player;
  u8 *childSlot;
  u8 *state;
  int i;
  u32 childCount;

  state = *(u8 **)(obj + 0xb8);
  *(int *)(obj + 0xbc) = (int)fn_8018728C;
  player = Obj_GetPlayerObject();
  if (*(s16 *)((u8 *)player + 0x46) != 0) {
    *(s16 *)(state + 0x20) = 0x13d;
  }
  else {
    *(s16 *)(state + 0x20) = 0x5d6;
  }

  *(u8 *)(state + 0x1c) = 0;
  *(u8 *)(state + 0x1d) = GameBit_Get(*(s16 *)(state + 0x20));

  if (*(s8 *)(def + 0x19) == 1) {
    if (*(u8 *)(state + 0x1d) != 0) {
      *(u8 *)(state + 0x1c) = 1;
      *(int *)state = fn_801871C8((int *)obj);
    }
    *(s16 *)(obj + 6) = *(s16 *)(obj + 6) | 0x4000;
  }
  else {
    childCount = *(u8 *)(state + 0x1d);
    if (childCount >= 6) {
      childCount = 6;
    }
    *(u8 *)(state + 0x1c) = (u8)childCount;

    i = 0;
    childSlot = state;
    while (i < *(u8 *)(state + 0x1c)) {
      *(int *)childSlot = fn_801871C8((int *)obj);
      childSlot += 4;
      i++;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80187664
 * EN v1.0 Address: 0x80187664
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x80187720
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80187664(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)
{
  uint uVar1;
  int iVar2;
  undefined2 *puVar3;
  double dVar4;
  
  uVar1 = FUN_80017ae8();
  if ((uVar1 & 0xff) == 0) {
    iVar2 = 0;
  }
  else {
    puVar3 = FUN_80017aa4(0x24,0x43c);
    *puVar3 = 0x43c;
    *(undefined *)(puVar3 + 1) = 9;
    *(undefined *)(puVar3 + 2) = 2;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 8;
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar4 = (double)FLOAT_803e4780;
    *(float *)(puVar3 + 6) = (float)(dVar4 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)((int)puVar3 + 0x19) = 4;
    puVar3[0xd] = 0x514;
    puVar3[0xe] = 0x28;
    *(undefined *)(puVar3 + 0xc) = 0x1e;
    iVar2 = FUN_80017a5c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar3);
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801877b0
 * EN v1.0 Address: 0x801877B0
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x801877E4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801877b0(int param_1,undefined4 param_2,int param_3)
{
  int iVar1;
  int *piVar2;
  int *piVar3;
  double dVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if ((*(char *)(param_3 + iVar1 + 0x81) == '\x01') && (*(byte *)(piVar3 + 7) != 0)) {
      if (piVar3[*(byte *)(piVar3 + 7) - 1] != 0) {
        (**(code **)(**(int **)(piVar3[*(byte *)(piVar3 + 7) - 1] + 0x68) + 0x24))();
      }
      *(char *)(piVar3 + 7) = *(char *)(piVar3 + 7) + -1;
      *(char *)((int)piVar3 + 0x1d) = *(char *)((int)piVar3 + 0x1d) + -1;
      GameBit_Set((int)*(short *)(piVar3 + 8),(uint)*(byte *)((int)piVar3 + 0x1d));
    }
  }
  *(byte *)((int)piVar3 + 0x1e) = *(byte *)((int)piVar3 + 0x1e) & 0x7f | 0x80;
  dVar4 = (double)FLOAT_803e4784;
  piVar2 = piVar3;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(piVar3 + 7); iVar1 = iVar1 + 1) {
    (**(code **)(**(int **)(*piVar2 + 0x68) + 0x28))
              ((double)*(float *)(param_1 + 0xc),
               (double)(float)(dVar4 + (double)*(float *)(param_1 + 0x10)),
               (double)*(float *)(param_1 + 0x14));
    piVar2 = piVar2 + 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801878f8
 * EN v1.0 Address: 0x801878F8
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80187930
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801878f8(int param_1)
{
  int iVar1;
  
  iVar1 = FUN_80017a90();
  if (iVar1 != 0) {
    FUN_8013651c(iVar1);
  }
  ObjGroup_RemoveObject(param_1,0xf);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018793c
 * EN v1.0 Address: 0x8018793C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80187974
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018793c(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018795c
 * EN v1.0 Address: 0x8018795C
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x80187998
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018795c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = *(int **)(param_9 + 0xb8);
  bVar1 = false;
  if (*(char *)(*(int *)(param_9 + 0x4c) + 0x19) == '\x01') {
    if (*(char *)(piVar3 + 7) != '\0') {
      if (*piVar3 != 0) {
        param_1 = (**(code **)(**(int **)(*piVar3 + 0x68) + 0x24))();
      }
      FUN_80017680((int)*(short *)(piVar3 + 8));
    }
    bVar1 = true;
  }
  else if (*(char *)((int)piVar3 + 0x1e) < '\0') {
    piVar4 = piVar3;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(piVar3 + 7); iVar2 = iVar2 + 1) {
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar4
                            );
      piVar4 = piVar4 + 1;
    }
    bVar1 = true;
  }
  if (bVar1) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187b14
 * EN v1.0 Address: 0x80187B14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80187A7C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187b14(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80187b18
 * EN v1.0 Address: 0x80187B18
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80187BA8
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187b18(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x31);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187b3c
 * EN v1.0 Address: 0x80187B3C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80187BCC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187b3c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187b64
 * EN v1.0 Address: 0x80187B64
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x80187BFC
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187b64(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  uint auStack_18 [4];
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (((*pbVar4 & 3) == 0) &&
     (iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,auStack_18), iVar1 == 0x1a)) {
    uVar2 = (uint)*(short *)(iVar3 + 0x1e);
    if (uVar2 != 0xffffffff) {
      GameBit_Set(uVar2,1);
      FUN_80006824(0,0x409);
    }
    *(float *)(pbVar4 + 4) = FLOAT_803e4794;
    *pbVar4 = *pbVar4 | 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187bf4
 * EN v1.0 Address: 0x80187BF4
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x80187C90
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187bf4(uint param_1)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar3 = FUN_80017a90();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  uVar4 = (uint)*(short *)(iVar5 + 0x20);
  if ((uVar4 == 0xffffffff) ||
     (((uVar4 = GameBit_Get(uVar4), uVar4 != 0 && (iVar3 != 0)) &&
      (uVar4 = GameBit_Get(0x245), uVar4 != 0)))) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if ((*pbVar6 & 3) == 0) {
    if (pbVar6[1] == 0) {
      ObjHits_SetHitVolumeSlot(param_1,9,1,0);
    }
    ObjHits_EnableObject(param_1);
    if (*(short *)(param_1 + 0x46) == 0x102) {
      iVar5 = FUN_8012efc4();
      if (iVar5 == -1) {
        *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0;
      }
      else {
        *(undefined *)(*(int *)(*(int *)(param_1 + 0x50) + 0x40) + 0x11) = 0x10;
      }
    }
    if (((iVar3 != 0) && (bVar2)) &&
       (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7,
       (*(byte *)(param_1 + 0xaf) & 4) != 0)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,4);
    }
  }
  fVar1 = FLOAT_803e4798;
  if (FLOAT_803e4798 < *(float *)(pbVar6 + 4)) {
    *(float *)(pbVar6 + 4) = *(float *)(pbVar6 + 4) - FLOAT_803dc074;
    if (*(float *)(pbVar6 + 4) <= fVar1) {
      *(undefined *)(param_1 + 0x36) = 0;
      *(float *)(pbVar6 + 4) = fVar1;
      *pbVar6 = *pbVar6 & 0xfe;
      *pbVar6 = *pbVar6 | 2;
      FUN_80017ad0(param_1);
      ObjHits_DisableObject(param_1);
    }
  }
  if ((*pbVar6 & 1) != 0) {
    if (FLOAT_803e479c <= *(float *)(pbVar6 + 4)) {
      *(float *)(pbVar6 + 0x10) =
           FLOAT_803e4790 - (*(float *)(pbVar6 + 4) - FLOAT_803e479c) / FLOAT_803e479c;
    }
    else {
      *(float *)(pbVar6 + 0x10) = FLOAT_803e4790;
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if ((fVar1 < FLOAT_803e47a0) && (FLOAT_803e479c < fVar1)) {
      FUN_800305c4((double)(FLOAT_803e4790 - (fVar1 - FLOAT_803e479c) / FLOAT_803e47a4),param_1);
    }
    fVar1 = *(float *)(pbVar6 + 4);
    if (fVar1 < FLOAT_803e47a8) {
      if (FLOAT_803e479c <= fVar1) {
        *(char *)(param_1 + 0x36) =
             (char)(int)(FLOAT_803e47ac * ((fVar1 - FLOAT_803e479c) / FLOAT_803e47b0));
      }
      else {
        *(undefined *)(param_1 + 0x36) = 0;
      }
    }
    *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) - FLOAT_803dc074;
    if (FLOAT_803e4798 < *(float *)(pbVar6 + 0xc)) {
      uVar4 = 0;
    }
    else {
      uVar4 = 3;
      *(float *)(pbVar6 + 0xc) = *(float *)(pbVar6 + 0xc) + FLOAT_803e4790;
    }
    FUN_80081110(param_1,3,0,uVar4,(undefined4 *)0x0);
    FUN_800068c4(param_1,0x9e);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80187ee0
 * EN v1.0 Address: 0x80187EE0
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80187F98
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80187ee0(undefined2 *param_1,int param_2)
{
  uint uVar1;
  byte *pbVar2;
  undefined8 local_28;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  ObjGroup_AddObject((int)param_1,0x31);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000);
  *(float *)(param_1 + 4) = FLOAT_803e47b8 * ((float)(local_28 - DOUBLE_803e47d0) / FLOAT_803e47bc);
  if (*(float *)(param_1 + 4) <= FLOAT_803e47c0) {
    *(float *)(param_1 + 4) = FLOAT_803e47c0;
  }
  ObjHitbox_SetCapsuleBounds((int)param_1,(short)(int)(FLOAT_803e47c4 * *(float *)(param_1 + 4)),0,
               (short)(int)(FLOAT_803e47c8 * *(float *)(param_1 + 4)));
  *(float *)(pbVar2 + 0x10) = FLOAT_803e47cc;
  FUN_800305c4((double)FLOAT_803e4798,(int)param_1);
  if (((int)*(short *)(param_2 + 0x1e) != 0xffffffff) &&
     (uVar1 = GameBit_Get((int)*(short *)(param_2 + 0x1e)), uVar1 != 0)) {
    FUN_80017ad0((int)param_1);
    ObjHits_DisableObject((int)param_1);
    *(undefined *)(param_1 + 0x1b) = 0;
    *pbVar2 = *pbVar2 | 2;
  }
  pbVar2[1] = *(byte *)(param_2 + 0x19);
  if (pbVar2[1] == 1) {
    ObjHits_MarkObjectPositionDirty((int)param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188038
 * EN v1.0 Address: 0x80188038
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80188108
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188038(void)
{
  (**(code **)(*DAT_803dd740 + 0x10))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018806c
 * EN v1.0 Address: 0x8018806C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80188138
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018806c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80286840();
  if ((*(char *)(*(int *)(iVar1 + 0xb8) + 10) == '\0') &&
     (iVar2 = (**(code **)(*DAT_803dd740 + 0xc))(iVar1,(int)visible), iVar2 != 0)) {
    FUN_8003b818(iVar1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801880e0
 * EN v1.0 Address: 0x801880E0
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x801881C8
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801880e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  byte bVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  uint auStack_18 [3];
  
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x4c);
  bVar1 = *(byte *)(iVar5 + 10);
  if (bVar1 == 1) {
    ObjHits_ClearHitVolumes(param_9);
    ObjHits_DisableObject(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    *(undefined *)(iVar5 + 10) = 2;
    *(float *)(iVar5 + 0xc) = FLOAT_803e47dc;
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
  }
  else if (bVar1 == 0) {
    (**(code **)(*DAT_803dd740 + 8))(param_9,iVar5);
    iVar4 = ObjHits_GetPriorityHit(param_9,(undefined4 *)0x0,(int *)0x0,auStack_18);
    if (iVar4 != 0) {
      (**(code **)(*DAT_803dd740 + 0x30))(param_9,iVar5);
      FUN_80006824(param_9,SFXen_rfall5_c);
      ObjHitbox_SetSphereRadius(param_9,0x28);
      uVar6 = ObjHits_SetHitVolumeSlot(param_9,5,4,0);
      uVar2 = FUN_80017ae8();
      if ((uVar2 & 0xff) != 0) {
        puVar3 = FUN_80017aa4(0x24,0x253);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
        FUN_80017ae4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                     *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                     in_r9,in_r10);
      }
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x355,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x352,0,0,0xffffffff,0);
      *(undefined *)(iVar5 + 10) = 1;
    }
  }
  else if (((bVar1 < 3) &&
           (*(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803dc074,
           FLOAT_803e47e0 < *(float *)(iVar5 + 0xc))) &&
          (iVar4 = FUN_800575b4((double)(*(float *)(param_9 + 0xa8) * *(float *)(param_9 + 8)),
                                (float *)(param_9 + 0xc)), iVar4 == 0)) {
    ObjHits_EnableObject(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    *(undefined *)(iVar5 + 10) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801883bc
 * EN v1.0 Address: 0x801883BC
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80188400
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801883bc(short *param_1,int param_2)
{
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[0x58] = param_1[0x58] | 0x2000;
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0x5c),0x21);
  (**(code **)(*DAT_803dd740 + 0x2c))(*(undefined4 *)(param_1 + 0x5c),1);
  return;
}

/*
 * --INFO--
 *
 * Function: infopoint_hitDetect
 * EN v1.0 Address: 0x8018843C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801884A0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void infopoint_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80188470
 * EN v1.0 Address: 0x80188470
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x801884D8
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188470(uint param_1)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(param_1 + 0x46) == 0x548) {
    uVar2 = GameBit_Get((int)*(short *)(iVar4 + 6));
    if ((uVar2 != 0) && (uVar2 = GameBit_Get((int)*(short *)(iVar4 + 4)), uVar2 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    uVar2 = GameBit_Get((int)*(short *)(iVar4 + 6));
    if ((uVar2 == 0) && (uVar2 = GameBit_Get((int)*(short *)(iVar4 + 4)), uVar2 != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  else if (*(short *)(iVar4 + 10) == 0) {
    if ((*(char *)(iVar4 + 8) == '\0') &&
       (uVar2 = GameBit_Get((int)*(short *)(iVar4 + 6)), uVar2 != 0)) {
      *(undefined2 *)(iVar4 + 10) = 10;
    }
    if ((*(char *)(iVar4 + 8) == '\x01') && (*(float *)(iVar3 + 0xc) <= *(float *)(param_1 + 0x10)))
    {
      *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e47e8;
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
      fVar1 = *(float *)(iVar3 + 0xc);
      if (*(float *)(param_1 + 0x10) <= fVar1) {
        *(float *)(param_1 + 0x10) = fVar1;
        *(float *)(param_1 + 0x28) = FLOAT_803e47ec * -*(float *)(param_1 + 0x28);
        fVar1 = *(float *)(param_1 + 0x28);
        if (fVar1 < FLOAT_803e47f0) {
          fVar1 = -fVar1;
        }
        if (fVar1 < FLOAT_803e47f4) {
          *(undefined *)(iVar4 + 8) = 2;
        }
      }
    }
  }
  else {
    *(short *)(iVar4 + 10) = *(short *)(iVar4 + 10) - (short)(int)FLOAT_803dc074;
    if (*(short *)(iVar4 + 10) < 1) {
      *(undefined *)(iVar4 + 8) = 1;
      if (*(char *)(iVar4 + 9) != '\0') {
        FUN_80006824(param_1,0x4bc);
        *(undefined *)(iVar4 + 9) = 0;
      }
      *(undefined2 *)(iVar4 + 10) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188668
 * EN v1.0 Address: 0x80188668
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801886D4
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188668(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018866c
 * EN v1.0 Address: 0x8018866C
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801887AC
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018866c(int param_1)
{
  uint uVar1;
  float fVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  uVar1 = GameBit_Get(0x1bf);
  if ((uVar1 == 0) || (uVar1 = GameBit_Get(0x1bd), uVar1 != 0)) {
    if (pfVar3[1] == 0.0) {
      fVar2 = (float)FUN_80017a98();
      pfVar3[1] = fVar2;
    }
    else {
      uVar1 = FUN_80294c04((int)pfVar3[1]);
      if (uVar1 == 0) {
        *pfVar3 = FLOAT_803e4800;
      }
      else {
        if (FLOAT_803e4800 == *pfVar3) {
          ObjHits_RecordObjectHit((int)pfVar3[1],param_1,'\x1c',0,1);
        }
        *pfVar3 = *pfVar3 + FLOAT_803dc074;
        if (FLOAT_803e4804 < *pfVar3) {
          ObjHits_RecordObjectHit((int)pfVar3[1],param_1,'\x1c',1,1);
          *pfVar3 = *pfVar3 - FLOAT_803e4804;
        }
      }
    }
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    GameBit_Set(0x1bd,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801887d8
 * EN v1.0 Address: 0x801887D8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80188964
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801887d8(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188800
 * EN v1.0 Address: 0x80188800
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x80188998
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188800(int param_1)
{
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_80006ba8(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188864
 * EN v1.0 Address: 0x80188864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801889FC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188864(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80188868
 * EN v1.0 Address: 0x80188868
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80188AE8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188868(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188890
 * EN v1.0 Address: 0x80188890
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x80188B18
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188890(short *param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  double dVar8;
  int local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  sVar1 = param_1[0x23];
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    pfVar7 = *(float **)(param_1 + 0x5c);
    piVar5 = ObjGroup_GetObjects(2,&local_38);
    for (; local_38 != 0; local_38 = local_38 + -1) {
      dVar8 = (double)FUN_8001771c((float *)(*piVar5 + 0x18),(float *)(param_1 + 0xc));
      if (dVar8 < (double)pfVar7[6]) {
        iVar6 = *(int *)(*piVar5 + 0x54);
        if (iVar6 != 0) {
          uStack_24 = (int)*(short *)(iVar6 + 0x5a) ^ 0x80000000;
          local_28 = 0x43300000;
          dVar8 = (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4818);
          FUN_80017a48(&local_34,param_1,(float *)(*piVar5 + 0xc));
          if (pfVar7[3] <= local_34) {
            fVar2 = FLOAT_803e4814;
            if (*pfVar7 < local_34) {
              fVar2 = local_34 - *pfVar7;
              fVar2 = fVar2 * fVar2;
            }
          }
          else {
            fVar2 = local_34 - pfVar7[3];
            fVar2 = fVar2 * fVar2;
          }
          if (pfVar7[4] <= local_30) {
            fVar3 = FLOAT_803e4814;
            if (pfVar7[1] < local_30) {
              fVar3 = local_30 - pfVar7[1];
              fVar3 = fVar3 * fVar3;
            }
          }
          else {
            fVar3 = local_30 - pfVar7[4];
            fVar3 = fVar3 * fVar3;
          }
          if (pfVar7[5] <= local_2c) {
            fVar4 = FLOAT_803e4814;
            if (pfVar7[2] < local_2c) {
              fVar4 = local_2c - pfVar7[2];
              fVar4 = fVar4 * fVar4;
            }
          }
          else {
            fVar4 = local_2c - pfVar7[5];
            fVar4 = fVar4 * fVar4;
          }
          if (FLOAT_803e4814 + fVar2 + fVar3 + fVar4 < (float)(dVar8 * dVar8)) {
            *(short **)(*(int *)(*piVar5 + 0x54) + 0x50) = param_1;
            *(undefined *)(*(int *)(*piVar5 + 0x54) + 0xad) = 1;
          }
        }
      }
      piVar5 = piVar5 + 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188a8c
 * EN v1.0 Address: 0x80188A8C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x80188CF0
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188a8c(float *param_1,float *param_2,float *param_3)
{
  float fVar1;
  
  fVar1 = *param_1;
  if (fVar1 <= *param_2) {
    if (fVar1 < *param_3) {
      *param_3 = fVar1;
    }
  }
  else {
    *param_2 = fVar1;
  }
  fVar1 = param_1[1];
  if (fVar1 <= param_2[1]) {
    if (fVar1 < param_3[1]) {
      param_3[1] = fVar1;
    }
  }
  else {
    param_2[1] = fVar1;
  }
  fVar1 = param_1[2];
  if (param_2[2] < fVar1) {
    param_2[2] = fVar1;
    return;
  }
  if (param_3[2] <= fVar1) {
    return;
  }
  param_3[2] = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188b14
 * EN v1.0 Address: 0x80188B14
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x80188D6C
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188b14(short *param_1,int param_2)
{
  short sVar1;
  uint uVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  float afStack_38 [4];
  undefined4 local_28;
  uint uStack_24;
  
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  uVar2 = (uint)*(byte *)(param_2 + 0x1b);
  if (uVar2 != 0) {
    local_28 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4828) / FLOAT_803e4820;
    if (*(float *)(param_1 + 4) == FLOAT_803e4814) {
      *(float *)(param_1 + 4) = FLOAT_803e4810;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
    uStack_24 = uVar2;
  }
  sVar1 = param_1[0x23];
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    pfVar3 = *(float **)(param_1 + 0x5c);
    iVar4 = *(int *)**(undefined4 **)(param_1 + 0x3e);
    FUN_800178b8(iVar4,0,pfVar3);
    FUN_800178b8(iVar4,0,pfVar3 + 3);
    for (iVar5 = 1; iVar5 < (int)(uint)*(ushort *)(iVar4 + 0xe4); iVar5 = iVar5 + 1) {
      FUN_800178b8(iVar4,iVar5,afStack_38);
      FUN_80188a8c(afStack_38,pfVar3,pfVar3 + 3);
    }
    FUN_80247edc((double)*(float *)(param_1 + 4),pfVar3,pfVar3);
    FUN_80247edc((double)*(float *)(param_1 + 4),pfVar3 + 3,pfVar3 + 3);
    dVar6 = SeekTwiceBeforeRead(pfVar3 + 3);
    dVar7 = SeekTwiceBeforeRead(pfVar3);
    if (dVar7 <= dVar6) {
      dVar6 = SeekTwiceBeforeRead(pfVar3 + 3);
    }
    else {
      dVar6 = SeekTwiceBeforeRead(pfVar3);
    }
    pfVar3[6] = (float)dVar6;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188d34
 * EN v1.0 Address: 0x80188D34
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80188F20
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188d34(void)
{
  int iVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined auStack_38 [12];
  float local_2c;
  float local_28;
  float local_24 [9];
  
  iVar2 = FUN_80286834();
  iVar4 = *(int *)(iVar2 + 0xb8);
  if (*(char *)(iVar4 + 0x1a) != '\0') {
    for (bVar3 = 0; bVar3 < 5; bVar3 = bVar3 + 1) {
      iVar1 = (uint)bVar3 * 8;
      ObjPath_GetPointWorldPosition(iVar2,(uint)(byte)(&DAT_8032267c)[iVar1],&local_2c,&local_28,local_24,0);
      local_2c = local_2c - *(float *)(iVar2 + 0xc);
      local_28 = local_28 - *(float *)(iVar2 + 0x10);
      local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
      FUN_800810f0((double)(*(float *)(iVar2 + 8) * (float)(&DAT_80322678)[(uint)bVar3 * 2]),iVar2,4
                   ,(uint)(byte)(&DAT_8032267d)[iVar1],(uint)(byte)(&DAT_8032267e)[iVar1],
                   (int)auStack_38);
    }
  }
  if (*(float *)(iVar4 + 0xc) != FLOAT_803e4830) {
    ObjPath_GetPointWorldPosition(iVar2,6,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80081108((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 0xc));
  }
  if (*(float *)(iVar4 + 8) != FLOAT_803e4830) {
    ObjPath_GetPointWorldPosition(iVar2,8,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80081108((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 8));
  }
  if (*(float *)(iVar4 + 4) != FLOAT_803e4830) {
    ObjPath_GetPointWorldPosition(iVar2,7,&local_2c,&local_28,local_24,0);
    local_2c = local_2c - *(float *)(iVar2 + 0xc);
    local_28 = local_28 - *(float *)(iVar2 + 0x10);
    local_24[0] = local_24[0] - *(float *)(iVar2 + 0x14);
    FUN_80081108((double)FLOAT_803e4834,(double)*(float *)(iVar4 + 4));
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80188f94
 * EN v1.0 Address: 0x80188F94
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x80189184
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80188f94(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x10);
  if (iVar1 != 0) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    ObjLink_DetachChild(param_9,*(int *)(iVar2 + 0x10));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189028
 * EN v1.0 Address: 0x80189028
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801891D4
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189028(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
    FUN_80188d34();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189054
 * EN v1.0 Address: 0x80189054
 * EN v1.0 Size: 2620b
 * EN v1.1 Address: 0x80189218
 * EN v1.1 Size: 1552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80189054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,int param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)
{
  undefined4 uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 uVar8;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  iVar5 = *(int *)(param_9 + 0xb8);
  iVar7 = 0;
  iVar4 = param_11;
  do {
    if ((int)(uint)*(byte *)(param_11 + 0x8b) <= iVar7) {
      return 0;
    }
    switch(*(undefined *)(param_11 + iVar7 + 0x81)) {
    case 2:
    case 0x65:
      iVar4 = *(int *)(iVar6 + 0x14);
      if (iVar4 == 0x49f5a) {
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x26);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x26);
        FUN_80042bec(uVar1,0);
        uVar1 = FUN_80044404(0xb);
        FUN_80042bec(uVar1,1);
      }
      else if (iVar4 < 0x49f5a) {
        if (iVar4 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
          param_1 = extraout_f1;
          if (cVar2 == '\x02') {
            FUN_80041ff8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
            iVar4 = 1;
            FUN_80042b9c(0,0,1);
            uVar1 = FUN_80044404(0xb);
            FUN_80042bec(uVar1,0);
          }
          else {
            FUN_80041ff8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
            iVar4 = 1;
            FUN_80042b9c(0,0,1);
            uVar1 = FUN_80044404(0x29);
            FUN_80042bec(uVar1,0);
          }
        }
        else {
          if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
          FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
          iVar4 = 1;
          FUN_80042b9c(0,0,1);
          uVar1 = FUN_80044404(0x29);
          FUN_80042bec(uVar1,0);
        }
      }
      else if (iVar4 == 0x4cd65) {
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x41);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x41);
        FUN_80042bec(uVar1,0);
        uVar1 = FUN_80044404(0xb);
        FUN_80042bec(uVar1,1);
      }
      else {
LAB_801893dc:
        FUN_80041ff8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x29);
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        uVar1 = FUN_80044404(0x29);
        FUN_80042bec(uVar1,0);
      }
      break;
    case 3:
    case 100:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        iVar4 = 0;
        param_12 = *DAT_803dd72c;
        param_1 = (**(code **)(param_12 + 0x50))(0xb,4);
      }
      else if (iVar3 < 0x49f5a) {
        if (iVar3 == 0x451b9) {
          cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
          param_1 = extraout_f1_00;
          if (cVar2 == '\x02') {
            uVar8 = extraout_f1_00;
            FUN_80042b9c(0,0,1);
            FUN_80044404(0xd);
            FUN_80043030(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            (**(code **)(*DAT_803dd72c + 0x50))(0xd,10,0);
            (**(code **)(*DAT_803dd72c + 0x50))(0xd,0xb,0);
            iVar4 = 0;
            param_12 = *DAT_803dd72c;
            param_1 = (**(code **)(param_12 + 0x50))(0xd,0xe);
          }
        }
        else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775)) {
          iVar4 = 1;
          FUN_80042b9c(0,0,1);
          FUN_80044404(7);
          param_1 = FUN_80043030(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
      }
      else if (iVar3 == 0x4cd65) {
        iVar4 = 1;
        FUN_80042b9c(0,0,1);
        FUN_80044404(0xb);
        param_1 = FUN_80043030(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      break;
    case 5:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        param_1 = extraout_f1_01;
        if (cVar2 == '\x02') {
          param_1 = FUN_80042800();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_801895a4:
          param_1 = FUN_80042800();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_801895a4;
      break;
    case 6:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x451b9) {
        cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd);
        param_1 = extraout_f1_02;
        if (cVar2 == '\x02') {
          param_1 = FUN_800427c8();
        }
      }
      else if (iVar3 < 0x451b9) {
        if (iVar3 == 0x43775) {
LAB_80189614:
          param_1 = FUN_800427c8();
        }
      }
      else if (iVar3 == 0x49f5a) goto LAB_80189614;
      break;
    case 7:
    case 0x66:
      iVar3 = *(int *)(iVar6 + 0x14);
      if (iVar3 == 0x49f5a) {
        param_1 = FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x32,
                               '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
      }
      else if (iVar3 < 0x49f5a) {
        if ((iVar3 == 0x451b9) &&
           (cVar2 = (**(code **)(*DAT_803dd72c + 0x40))(0xd), param_1 = extraout_f1_03,
           cVar2 == '\x02')) {
          iVar4 = *DAT_803dd72c;
          uVar8 = (**(code **)(iVar4 + 0x44))(0xb,5);
          param_1 = FUN_80053c98(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4e,
                                 '\0',iVar4,param_12,param_13,param_14,param_15,param_16);
        }
      }
      else if (iVar3 == 0x4cd65) {
        FUN_80053c98(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x7f,'\0',iVar4
                     ,param_12,param_13,param_14,param_15,param_16);
        iVar4 = *DAT_803dd72c;
        param_1 = (**(code **)(iVar4 + 0x44))(0x41,2);
      }
      break;
    case 10:
      *(undefined *)(iVar5 + 0x1a) = 1;
      break;
    case 0xb:
      *(undefined *)(iVar5 + 0x1a) = 0;
      break;
    case 0xc:
      *(float *)(iVar5 + 4) = FLOAT_803e4830;
      break;
    case 0xd:
      *(float *)(iVar5 + 4) = FLOAT_803e4840;
      break;
    case 0xe:
      *(float *)(iVar5 + 4) = FLOAT_803e4844;
      break;
    case 0xf:
      *(float *)(iVar5 + 4) = FLOAT_803e4848;
      break;
    case 0x10:
      *(float *)(iVar5 + 8) = FLOAT_803e4830;
      break;
    case 0x11:
      *(float *)(iVar5 + 8) = FLOAT_803e4840;
      break;
    case 0x12:
      *(float *)(iVar5 + 8) = FLOAT_803e4844;
      break;
    case 0x13:
      *(float *)(iVar5 + 8) = FLOAT_803e4848;
      break;
    case 0x14:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4830;
      break;
    case 0x15:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4840;
      break;
    case 0x16:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4844;
      break;
    case 0x17:
      *(float *)(iVar5 + 0xc) = FLOAT_803e4848;
      break;
    case 0x18:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) & 0xbfff;
      }
      break;
    case 0x19:
      iVar3 = *(int *)(iVar5 + 0x10);
      if (iVar3 != 0) {
        *(ushort *)(iVar3 + 6) = *(ushort *)(iVar3 + 6) | 0x4000;
      }
    }
    iVar7 = iVar7 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80189a90
 * EN v1.0 Address: 0x80189A90
 * EN v1.0 Size: 1028b
 * EN v1.1 Address: 0x80189828
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189a90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  undefined2 *puVar4;
  float fVar5;
  char cVar6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar7;
  int iVar8;
  undefined8 extraout_f1;
  
  pfVar7 = *(float **)(param_9 + 0xb8);
  iVar2 = FUN_80017a98();
  if ((pfVar7[4] == 0.0) && (uVar3 = FUN_80017ae8(), (uVar3 & 0xff) != 0)) {
    puVar4 = FUN_80017aa4(0x24,0x606);
    fVar5 = (float)FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar4,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    pfVar7[4] = fVar5;
    param_1 = extraout_f1;
    if (pfVar7[4] != 0.0) {
      ObjLink_AttachChild(param_9,(int)pfVar7[4],0);
      param_1 = FUN_8020a758((int)pfVar7[4],0xaf);
      *(ushort *)((int)pfVar7[4] + 6) = *(ushort *)((int)pfVar7[4] + 6) | 0x4000;
    }
  }
  if (pfVar7[4] != 0.0) {
    param_1 = FUN_8020a75c((int)pfVar7[4]);
  }
  if ((iVar2 == 0) || (iVar2 = FUN_80294dbc(iVar2), iVar2 == 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 0x10;
  }
  bVar1 = *(byte *)((int)pfVar7 + 0x16);
  if (bVar1 == 1) {
    iVar2 = ObjTrigger_IsSet(param_9);
    if (iVar2 != 0) {
      *(undefined *)((int)pfVar7 + 0x16) = 2;
      FUN_8011d9b4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    ObjHits_PollPriorityHitEffectWithCooldown(param_9,8,0xb4,0xf0,0xff,0x6f,pfVar7);
  }
  else if (bVar1 == 0) {
    iVar2 = ObjTrigger_IsSet(param_9);
    if (iVar2 != 0) {
      iVar8 = *(int *)(param_9 + 0x4c);
      iVar2 = ObjGroup_FindNearestObject(0xf,param_9,(float *)0x0);
      if ((*(char *)(param_9 + 0xac) == '\r') && (uVar3 = GameBit_Get(0xc92), uVar3 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e4838;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar2,0xffffffff);
      }
      GameBit_Set((int)*(short *)(iVar8 + 0x1c),0);
    }
  }
  else if (bVar1 < 3) {
    cVar6 = FUN_8012e0e0();
    if (cVar6 == '\0') {
      *(undefined *)((int)pfVar7 + 0x16) = 1;
    }
    else {
      iVar8 = *(int *)(param_9 + 0x4c);
      iVar2 = ObjGroup_FindNearestObject(0xf,param_9,(float *)0x0);
      if ((*(char *)(param_9 + 0xac) == '\r') && (uVar3 = GameBit_Get(0xc92), uVar3 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e4838;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,iVar2,0xffffffff);
      }
      GameBit_Set((int)*(short *)(iVar8 + 0x1c),0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80189e94
 * EN v1.0 Address: 0x80189E94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80189AF8
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80189e94(int param_1,int param_2)
{
}


/* Trivial 4b 0-arg blr leaves. */
void flammablevine_release(void) {}
void flammablevine_initialise(void) {}
void dll_109_hitDetect_nop(void) {}
void dll_109_release_nop(void) {}
void dll_109_initialise_nop(void) {}
void Fall_Ladders_render(void) {}
void Fall_Ladders_hitDetect(void) {}
void Fall_Ladders_release(void) {}
void Fall_Ladders_initialise(void) {}
void infopoint_free(void) {}
void infopoint_release(void) {}
void infopoint_initialise(void) {}
void decoration11a_free(void) {}
void decoration11a_update(void) {}

/* 8b "li r3, N; blr" returners. */
int flammablevine_getExtraSize(void) { return 0x14; }
int flammablevine_getObjectTypeId(void) { return 0x0; }
int dll_109_getExtraSize_ret_16(void) { return 0x10; }
int dll_109_getObjectTypeId(void) { return 0x0; }
int return0_80187F30(void) { return 0x0; }
int Fall_Ladders_getExtraSize(void) { return 0xc; }
int Fall_Ladders_getObjectTypeId(void) { return 0x0; }
int coldwatercontrol_getExtraSize(void) { return 0x8; }
int infopoint_getExtraSize(void) { return 0x20; }
int infopoint_getObjectTypeId(void) { return 0x0; }
int decoration11a_getExtraSize(void) { return 0x1c; }
int landed_arwing_getExtraSize(void) { return 0x1c; }

typedef struct FallLaddersState {
    f32 restYOffset;
    s16 lowerGameBit;
    s16 upperGameBit;
    u8 motionState;
    u8 playStartSound;
    s16 delay;
} FallLaddersState;

typedef struct CarryableBreakRespawnState {
    u8 pad0[0xa];
    u8 state;
    u8 padB;
    f32 timer;
} CarryableBreakRespawnState;

extern int *lbl_803DCAC0;
extern int *gPartfxInterface;
extern undefined4* gObjectTriggerInterface;
extern f32 timeDelta;
extern f32 lbl_803E3B44;
extern f32 lbl_803E3B48;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int ViewFrustum_IsSphereVisible(f32 *pos, f32 radius);
typedef void (*ObjectTriggerUpdateFn)(int, int, int);
typedef void (*PartfxSpawnFn)(int, int, int, int, int, int);

/* Carryable impact state machine that spawns break particles, hides, then respawns. */
#pragma scheduling off
#pragma peephole off
void carryable_break_respawn_update(int obj) {
    CarryableBreakRespawnState *state;
    int def;
    int setup;
    u32 hitVolume;

    state = *(CarryableBreakRespawnState **)(obj + 0xb8);
    def = *(int *)(obj + 0x4c);
    switch (state->state) {
        case 0:
            (*(void (*)(int, CarryableBreakRespawnState *))(*(int *)(*lbl_803DCAC0 + 8)))(obj, state);
            if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) != 0) {
                (*(void (*)(int, CarryableBreakRespawnState *))(*(int *)(*lbl_803DCAC0 + 0x30)))(obj, state);
                Sfx_PlayFromObject(obj, SFXen_rfall5_c);
                ObjHitbox_SetSphereRadius(obj, 0x28);
                ObjHits_SetHitVolumeSlot(obj, 5, 4, 0);
                if (Obj_IsLoadingLocked() != 0) {
                    setup = Obj_AllocObjectSetup(0x24, 0x253);
                    *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                    *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                    *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                    Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(int *)(obj + 0x30));
                }
                ((PartfxSpawnFn)(*(u32 *)(*gPartfxInterface + 8)))(obj, 0x355, 0, 0, -1, 0);
                ((PartfxSpawnFn)(*(u32 *)(*gPartfxInterface + 8)))(obj, 0x352, 0, 0, -1, 0);
                state->state = 1;
            }
            break;
        case 1:
            ObjHits_ClearHitVolumes();
            ObjHits_DisableObject(obj);
            *(u8 *)(obj + 0xaf) |= 8;
            state->state = 2;
            state->timer = lbl_803E3B44;
            *(f32 *)(obj + 0xc) = *(f32 *)(def + 8);
            *(f32 *)(obj + 0x10) = *(f32 *)(def + 0xc);
            *(f32 *)(obj + 0x14) = *(f32 *)(def + 0x10);
            break;
        case 2:
            state->timer += timeDelta;
            if (state->timer > lbl_803E3B48) {
                if (ViewFrustum_IsSphereVisible((f32 *)(obj + 0xc),
                                                *(f32 *)(obj + 0xa8) * *(f32 *)(obj + 8)) == 0) {
                    ObjHits_EnableObject(obj);
                    *(u8 *)(obj + 0xaf) &= ~8;
                    state->state = 0;
                }
            }
            break;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3AF8;
extern f32 lbl_803E3AFC;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B14;
extern f32 lbl_803E3B18;
extern f32 lbl_803E3B1C;
extern f32 lbl_803E3B20;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;
extern void objRenderFn_8003b8f4(f32);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjAnim_SetMoveProgress(int obj, f32 progress);
extern void objRemoveFromListFn_8002ce88(int obj);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);
extern int cMenuGetSelectedItem(void);
extern f32 timeDelta;
extern void *getTrickyObject(void);
extern f32 lbl_803E3B70;
extern f32 lbl_803E3B78;
#pragma peephole off
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3AF8); }
void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3B70); }
void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3B78); }
#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void flammablevine_free(int x) { ObjGroup_RemoveObject(x, 0x31); }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void flammablevine_hitDetect(int obj)
{
    u8 *state;
    u8 *def;
    int hitObj;

    state = *(u8 **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    if ((state[0] & 3) == 0) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitObj) == 0x1a) {
            if (*(s16 *)(def + 0x1e) != -1) {
                GameBit_Set(*(s16 *)(def + 0x1e), 1);
                Sfx_PlayFromObject(0, 0x409);
            }
            *(f32 *)(state + 4) = lbl_803E3AFC;
            state[0] = state[0] | 1;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void flammablevine_init(int obj, int def)
{
    u8 *state;
    f32 scale;

    state = *(u8 **)(obj + 0xb8);
    ObjGroup_AddObject(obj, 0x31);
    *(s16 *)obj = (s16)((s8)*(u8 *)(def + 0x18) << 8);

    *(f32 *)(obj + 8) = lbl_803E3B20 * ((f32)*(s16 *)(def + 0x1a) / lbl_803E3B24);
    if (*(f32 *)(obj + 8) <= lbl_803E3B28) {
        *(f32 *)(obj + 8) = lbl_803E3B28;
    }

    scale = *(f32 *)(obj + 8);
    ObjHitbox_SetCapsuleBounds(
        obj,
        (s16)(lbl_803E3B2C * scale),
        0,
        (s16)(lbl_803E3B30 * scale));
    *(f32 *)(state + 0x10) = lbl_803E3B34;
    ObjAnim_SetMoveProgress(obj, lbl_803E3B00);

    if (*(s16 *)(def + 0x1e) != -1 && GameBit_Get(*(s16 *)(def + 0x1e)) != 0) {
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
        *(u8 *)(obj + 0x36) = 0;
        state[0] = state[0] | 2;
    }

    state[1] = *(u8 *)(def + 0x19);
    if (state[1] == 1) {
        ObjHits_MarkObjectPositionDirty(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void flammablevine_update(int obj)
{
    u8 *state;
    u8 *def;
    void *tricky;
    u8 canUse;
    f32 burnTimer;
    f32 zero;
    int pulseStyle;
    u32 fadeAlpha;

    state = *(u8 **)(obj + 0xb8);
    def = *(u8 **)(obj + 0x4c);
    tricky = getTrickyObject();

    *(u8 *)(obj + 0xaf) = *(u8 *)(obj + 0xaf) | 8;
    if (*(s16 *)(def + 0x20) == -1) {
        goto can_use_vine;
    }
    if (GameBit_Get(*(s16 *)(def + 0x20)) == 0) {
        goto cant_use_vine;
    }
    if (tricky == NULL) {
        goto cant_use_vine;
    }
    if (GameBit_Get(0x245) == 0) {
        goto cant_use_vine;
    }
can_use_vine:
    canUse = 1;
    goto checked_vine_use;
cant_use_vine:
    canUse = 0;
checked_vine_use:

    if ((state[0] & 3) == 0) {
        if (state[1] == 0) {
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
        }
        ObjHits_EnableObject(obj);

        if (*(s16 *)(obj + 0x46) == 0x102) {
            if (cMenuGetSelectedItem() == -1) {
                *(u8 *)(*(int *)(*(int *)(obj + 0x50) + 0x40) + 0x11) = 0;
            }
            else {
                *(u8 *)(*(int *)(*(int *)(obj + 0x50) + 0x40) + 0x11) = 0x10;
            }
        }

        if (tricky != NULL && canUse != 0) {
            *(u8 *)(obj + 0xaf) = *(u8 *)(obj + 0xaf) & ~8;
            if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                ((void (*)(void *, int, int, int))(*(int *)(*(int *)(*(int *)((u8 *)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = *(f32 *)(state + 4);
    zero = lbl_803E3B00;
    if (burnTimer > zero) {
        *(f32 *)(state + 4) = burnTimer - timeDelta;
        if (*(f32 *)(state + 4) <= zero) {
            *(u8 *)(obj + 0x36) = 0;
            *(f32 *)(state + 4) = zero;
            state[0] = state[0] & ~1;
            state[0] = state[0] | 2;
            objRemoveFromListFn_8002ce88(obj);
            ObjHits_DisableObject(obj);
        }
    }

    if ((state[0] & 1) != 0) {
        if (*(f32 *)(state + 4) < lbl_803E3B04) {
            *(f32 *)(state + 0x10) = lbl_803E3AF8;
        }
        else {
            *(f32 *)(state + 0x10) = lbl_803E3AF8 - ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B04);
        }

        if (*(f32 *)(state + 4) < lbl_803E3B08 && *(f32 *)(state + 4) > lbl_803E3B04) {
            ObjAnim_SetMoveProgress(
                obj,
                lbl_803E3AF8 - ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B0C));
        }

        if (*(f32 *)(state + 4) < lbl_803E3B10) {
            if (*(f32 *)(state + 4) < lbl_803E3B04) {
                *(u8 *)(obj + 0x36) = 0;
            }
            else {
                fadeAlpha = (u8)(lbl_803E3B14 * ((*(f32 *)(state + 4) - lbl_803E3B04) / lbl_803E3B18));
                *(u8 *)(obj + 0x36) = fadeAlpha;
            }
        }

        *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) - timeDelta;
        if (*(f32 *)(state + 0xc) <= lbl_803E3B00) {
            pulseStyle = 3;
            *(f32 *)(state + 0xc) = *(f32 *)(state + 0xc) + lbl_803E3AF8;
        }
        else {
            pulseStyle = 0;
        }
        fn_80098B18(obj, lbl_803E3B1C * (*(f32 *)(state + 0x10) * *(f32 *)(obj + 8)), 3, 0, pulseStyle, 0);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* Fall_Ladders_free: vtable method @ 0x18 on global manager. */
extern undefined4* gExpgfxInterface;
typedef void (*FallLaddersFreeFn)(int);
#pragma scheduling off
void Fall_Ladders_free(int obj) {
    ((FallLaddersFreeFn)(*(u32*)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset

/* coldwatercontrol_init: set float field + OR flag bits. */
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern int fn_80295C40(int obj);
extern undefined4* gObjectTriggerInterface;
typedef void (*InfoPtUpdateFn)(int, int, int);
#pragma scheduling off
#pragma peephole off
void coldwatercontrol_update(int obj) {
    u8 *state;

    state = *(u8 **)(obj + 0xb8);
    if (GameBit_Get(0x1bf) != 0 && GameBit_Get(0x1bd) == 0) {
        ((InfoPtUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        GameBit_Set(0x1bd, 1);
        return;
    }

    if (*(void **)(state + 4) != NULL) {
        if (fn_80295C40(*(int *)(state + 4)) != 0) {
            if (lbl_803E3B68 == *(f32 *)state) {
                ObjHits_RecordObjectHit(*(int *)(state + 4), obj, 0x1c, 0, 1);
            }

            *(f32 *)state = *(f32 *)state + timeDelta;
            if (*(f32 *)state > lbl_803E3B6C) {
                ObjHits_RecordObjectHit(*(int *)(state + 4), obj, 0x1c, 1, 1);
                *(f32 *)state = *(f32 *)state - lbl_803E3B6C;
            }
        }
        else {
            *(f32 *)state = lbl_803E3B68;
        }
    }
    else {
        *(int *)(state + 4) = (int)Obj_GetPlayerObject();
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void coldwatercontrol_init(int obj) {
    int *p = ((int**)obj)[0xb8/4];
    *(f32*)p = lbl_803E3B68;
    *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x6000);
}
#pragma peephole reset
#pragma scheduling reset

/* landed_arwing_free: free child object + detach link. */
extern void Obj_FreeObject(int obj);
#pragma scheduling off
#pragma peephole off
void landed_arwing_free(int obj) {
    int o = obj;
    int *p = ((int**)o)[0xb8/4];
    if (*(void**)&p[0x10/4] != NULL) {
        Obj_FreeObject(p[0x10/4]);
        ObjLink_DetachChild(o, p[0x10/4]);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* landed_arwing_render: visible-guarded render with extra call. */
extern f32 lbl_803E3BA4;
extern void landed_arwing_renderPathEffects(int obj);
#pragma peephole off
#pragma scheduling off
void landed_arwing_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    s32 v = visible;
    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E3BA4);
        landed_arwing_renderPathEffects(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

typedef struct LandedArwingFxPoint {
    f32 scale;
    u8 pathPoint;
    u8 arg5;
    u8 arg6;
    u8 pad;
} LandedArwingFxPoint;

typedef struct LandedArwingFxScratch {
    u8 effectPos[12];
    f32 x;
    f32 y;
    f32 z;
} LandedArwingFxScratch;

typedef struct LandedArwingState {
    f32 unk0;
    f32 path7Fx;
    f32 path8Fx;
    f32 path6Fx;
    int childObject;
    s16 unk14;
    u8 sequenceState;
    u8 unk17;
    u8 unk18;
    u8 unk19;
    u8 enablePathFx;
    u8 unk1B;
    u8 hitStarted;
    u8 hitFlags;
    u8 unk1E;
    u8 spawnCount;
    u8 hitCooldown[4];
} LandedArwingState;

typedef struct LandedArwingHitFlagBits {
    u8 damaged:1;
    u8 impactHandled:1;
    u8 gameBit24Set:1;
    u8 reactionDone:1;
    u8 rest:4;
} LandedArwingHitFlagBits;

extern LandedArwingFxPoint lbl_80321A28[];
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern void objfx_spawnMaskedHitEffect(int obj, int arg4, int arg5, int arg6, void *pos, f32 scale);
extern void objfx_spawnLightPulse(int obj, int arg4, int arg5, int arg6, void *pos, f32 scale, f32 value);

#pragma scheduling off
#pragma peephole off
void landed_arwing_renderPathEffects(int obj) {
    LandedArwingState *state;
    u8 i;
    LandedArwingFxPoint *entry;
    LandedArwingFxScratch scratch;
    f32 *xPtr;
    f32 *yPtr;
    f32 *zPtr;

    state = *(LandedArwingState **)(obj + 0xb8);
    if (state->enablePathFx != 0) {
        i = 0;
        zPtr = &scratch.z;
        yPtr = &scratch.y;
        xPtr = &scratch.x;
        while (i < 5) {
            entry = &lbl_80321A28[i];
            ObjPath_GetPointWorldPosition(obj, entry->pathPoint, xPtr, yPtr, zPtr, 0);
            *xPtr -= *(f32 *)(obj + 0xc);
            *yPtr -= *(f32 *)(obj + 0x10);
            *zPtr -= *(f32 *)(obj + 0x14);
            objfx_spawnMaskedHitEffect(obj, 4, entry->arg5, entry->arg6, scratch.effectPos,
                        *(f32 *)(obj + 8) * entry->scale);
            i++;
        }
    }

    if (state->path6Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 6, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= *(f32 *)(obj + 0xc);
        scratch.y -= *(f32 *)(obj + 0x10);
        scratch.z -= *(f32 *)(obj + 0x14);
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path6Fx);
    }

    if (state->path8Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 8, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= *(f32 *)(obj + 0xc);
        scratch.y -= *(f32 *)(obj + 0x10);
        scratch.z -= *(f32 *)(obj + 0x14);
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path8Fx);
    }

    if (state->path7Fx != lbl_803E3B98) {
        ObjPath_GetPointWorldPosition(obj, 7, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= *(f32 *)(obj + 0xc);
        scratch.y -= *(f32 *)(obj + 0x10);
        scratch.z -= *(f32 *)(obj + 0x14);
        objfx_spawnLightPulse(obj, 4, 0, 0, scratch.effectPos, lbl_803E3B9C, state->path7Fx);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int dirIdx, int locked);
extern void mapUnload(int dirIdx, int flags);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void warpToMap(int mapId, int arg);
extern void unlockLevel(int a, int b, int c);
extern MapEventInterface **gMapEventInterface;
extern f32 lbl_803E3BA8;
extern f32 lbl_803E3BAC;
extern f32 lbl_803E3BB0;

#define MAP_EVENT_STATUS(mapId) (*gMapEventInterface)->getMode((mapId))
#define MAP_EVENT_SET(mapId, value) (*gMapEventInterface)->setMode((mapId), (value))
#define MAP_EVENT_OP(mapId, arg, value) (*gMapEventInterface)->setAnimEvent((mapId), (arg), (value))

#pragma scheduling off
#pragma peephole off
int Landed_Arwing_SeqFn(int obj, int unused, u8 *events) {
    int i;
    int def;
    LandedArwingState *state;
    int mapId;
    int child;

    def = *(int *)(obj + 0x4c);
    state = *(LandedArwingState **)(obj + 0xb8);
    for (i = 0; i < events[0x8b]; i++) {
        switch (events[0x81 + i]) {
            case 2:
            case 0x65:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x49f5a) {
                    loadMapAndParent(0x26);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x26), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            loadMapAndParent(0xb);
                            unlockLevel(0, 0, 1);
                            lockLevel(mapGetDirIdx(0xb), 0);
                        } else {
                            loadMapAndParent(0x29);
                            unlockLevel(0, 0, 1);
                            lockLevel(mapGetDirIdx(0x29), 0);
                        }
                    } else if (mapId == 0x43775) {
                        loadMapAndParent(0x29);
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x29), 0);
                    } else {
                        loadMapAndParent(0x29);
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x29), 0);
                    }
                } else if (mapId == 0x4cd65) {
                    loadMapAndParent(0x41);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x41), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                } else {
                    loadMapAndParent(0x29);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x29), 0);
                }
                break;
            case 3:
            case 0x64:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x49f5a) {
                    MAP_EVENT_OP(0xb, 4, 0);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            unlockLevel(0, 0, 1);
                            mapUnload(mapGetDirIdx(0xd), 0x3f3f);
                            MAP_EVENT_OP(0xd, 0xa, 0);
                            MAP_EVENT_OP(0xd, 0xb, 0);
                            MAP_EVENT_OP(0xd, 0xe, 0);
                        }
                    } else if (mapId == 0x43775) {
                        unlockLevel(0, 0, 1);
                        mapUnload(mapGetDirIdx(7), 0x3f3c);
                    }
                } else if (mapId == 0x4cd65) {
                    unlockLevel(0, 0, 1);
                    mapUnload(mapGetDirIdx(0xb), 0x3f00);
                }
                break;
            case 5:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x451b9) {
                    if (MAP_EVENT_STATUS(0xd) == 2) {
                        setLoadedFileFlags_blocks1();
                    }
                } else if (mapId < 0x451b9) {
                    if (mapId == 0x43775) {
                        setLoadedFileFlags_blocks1();
                    }
                } else if (mapId == 0x49f5a) {
                    setLoadedFileFlags_blocks1();
                }
                break;
            case 6:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x451b9) {
                    if (MAP_EVENT_STATUS(0xd) == 2) {
                        clearLoadedFileFlags_blocks1();
                    }
                } else if (mapId < 0x451b9) {
                    if (mapId == 0x43775) {
                        clearLoadedFileFlags_blocks1();
                    }
                } else if (mapId == 0x49f5a) {
                    clearLoadedFileFlags_blocks1();
                }
                break;
            case 7:
            case 0x66:
                mapId = *(int *)(def + 0x14);
                if (mapId == 0x49f5a) {
                    warpToMap(0x32, 0);
                } else if (mapId < 0x49f5a) {
                    if (mapId == 0x451b9) {
                        if (MAP_EVENT_STATUS(0xd) == 2) {
                            MAP_EVENT_SET(0xb, 5);
                            warpToMap(0x4e, 0);
                        }
                    }
                } else if (mapId == 0x4cd65) {
                    warpToMap(0x7f, 0);
                    MAP_EVENT_SET(0x41, 2);
                }
                break;
            case 0xa:
                state->enablePathFx = 1;
                break;
            case 0xb:
                state->enablePathFx = 0;
                break;
            case 0xc:
                state->path7Fx = lbl_803E3B98;
                break;
            case 0xd:
                state->path7Fx = lbl_803E3BA8;
                break;
            case 0xe:
                state->path7Fx = lbl_803E3BAC;
                break;
            case 0xf:
                state->path7Fx = lbl_803E3BB0;
                break;
            case 0x10:
                state->path8Fx = lbl_803E3B98;
                break;
            case 0x11:
                state->path8Fx = lbl_803E3BA8;
                break;
            case 0x12:
                state->path8Fx = lbl_803E3BAC;
                break;
            case 0x13:
                state->path8Fx = lbl_803E3BB0;
                break;
            case 0x14:
                state->path6Fx = lbl_803E3B98;
                break;
            case 0x15:
                state->path6Fx = lbl_803E3BA8;
                break;
            case 0x16:
                state->path6Fx = lbl_803E3BAC;
                break;
            case 0x17:
                state->path6Fx = lbl_803E3BB0;
                break;
            case 0x18:
                child = state->childObject;
                if (child != 0) {
                    *(u16 *)(child + 6) &= 0xbfff;
                }
                break;
            case 0x19:
                child = state->childObject;
                if (child != 0) {
                    *(u16 *)(child + 6) |= 0x4000;
                }
                break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void fn_8022F270(int obj, int arg);
extern void fn_8022F27C(int obj);
extern int fn_802972A8(int obj);
extern u8 fn_8012DDA4(void);
extern void cutSceneFn_8011dd30(void);
extern f32 lbl_803E3BA0;

#pragma scheduling off
#pragma peephole off
void landed_arwing_update(int obj) {
    LandedArwingState *state;
    int player;
    int child;
    int def;
    int nearest;

    state = *(LandedArwingState **)(obj + 0xb8);
    player = (int)Obj_GetPlayerObject();
    if (state->childObject == 0) {
        if (Obj_IsLoadingLocked() != 0) {
            child = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x606), 4, -1, -1, 0);
            state->childObject = child;
            if (state->childObject != 0) {
                ObjLink_AttachChild(obj, state->childObject, 0);
                fn_8022F270(state->childObject, 0xaf);
                *(u16 *)(state->childObject + 6) |= 0x4000;
            }
        }
    }

    if (state->childObject != 0) {
        fn_8022F27C(state->childObject);
    }

    if (player != 0 && fn_802972A8(player) != 0) {
        *(u8 *)(obj + 0xaf) |= 0x10;
    } else {
        *(u8 *)(obj + 0xaf) &= 0xef;
    }

    switch (state->sequenceState) {
        case 0:
            if (ObjTrigger_IsSet(obj) != 0) {
                def = *(int *)(obj + 0x4c);
                nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
                if (*(s8 *)(obj + 0xac) == 0xd && GameBit_Get(0xc92) != 0) {
                    *(f32 *)(nearest + 0x10) += lbl_803E3BA0;
                    ((InfoPtUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(2, nearest, -1);
                } else {
                    ((InfoPtUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(1, nearest, -1);
                }
                GameBit_Set(*(s16 *)(def + 0x1c), 0);
            }
            break;
        case 1:
            if (ObjTrigger_IsSet(obj) != 0) {
                state->sequenceState = 2;
                cutSceneFn_8011dd30();
            }
            ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f, state);
            break;
        case 2:
            if (fn_8012DDA4() != 0) {
                def = *(int *)(obj + 0x4c);
                nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
                if (*(s8 *)(obj + 0xac) == 0xd && GameBit_Get(0xc92) != 0) {
                    *(f32 *)(nearest + 0x10) += lbl_803E3BA0;
                    ((InfoPtUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(2, nearest, -1);
                } else {
                    ((InfoPtUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(1, nearest, -1);
                }
                GameBit_Set(*(s16 *)(def + 0x1c), 0);
            } else {
                state->sequenceState = 1;
            }
            break;
    }
}
#pragma peephole reset
#pragma scheduling reset

/* infopoint_update: if low bit on 0xaf, disable button + vtable[0x48]. */
extern void buttonDisable(int p1, int mask);
#pragma scheduling off
#pragma peephole off
void infopoint_update(int obj) {
    if ((*(u8*)((char*)obj + 0xaf) & 1) != 0) {
        buttonDisable(0, 0x100);
        ((InfoPtUpdateFn)(*(u32*)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* landed_arwing_init: flag bits, counter, conditional unlock, set callback. */
extern int Landed_Arwing_SeqFn(int obj, int unused, u8 *events);
#pragma scheduling off
#pragma peephole off
void landed_arwing_init(int obj, int param) {
    int *p = ((int**)obj)[0xb8/4];
    *(u16*)((char*)obj + 0xb0) = *(u16*)((char*)obj + 0xb0) | 0x2000;
    *(s8*)((char*)p + 0x16) = 1;
    if (GameBit_Get(*(s16*)((char*)param + 0x1c)) == 0) {
        unlockLevel(0, 0, 1);
    }
    *(int *)((char*)obj + 0xbc) = (int)Landed_Arwing_SeqFn;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;
extern f32 timeDelta;
extern int ObjAnim_AdvanceCurrentMove(int obj, f32 rate, f32 delta, void *out);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);

/* landed arwing hit/animation step: handles impact reactions and spawned debris. */
#pragma scheduling off
#pragma peephole off
void landed_arwing_updateHitReaction(int obj, LandedArwingState *state) {
    int def;
    int i;
    int setup;
    int other;
    LandedArwingState *otherState;
    f32 range;
    f32 yOffset;
    u8 animScratch[0x34];

    def = *(int *)(obj + 0x4c);
    if (((state->hitFlags >> 7) & 1) != 0) {
        if (((state->hitFlags >> 6) & 1) != 0 && state->hitStarted == 0) {
            return;
        }
        if (state->hitStarted != 0) {
            *(s16 *)(obj + 2) = 0;
            *(s16 *)(obj + 4) = 0;
            if (*(f32 *)(obj + 0x98) >= lbl_803E3BBC && ((state->hitFlags >> 4) & 1) == 0) {
                if (*(s16 *)(def + 0x24) > 0) {
                    GameBit_Set(*(s16 *)(def + 0x24), 1);
                }

                switch (*(u8 *)(def + 0x1e)) {
                    case 0:
                        if (Obj_IsLoadingLocked() != 0) {
                            yOffset = lbl_803E3BB8;
                            for (i = 0; i < *(u8 *)(def + 0x1f); i++) {
                                setup = Obj_AllocObjectSetup(0x24, 0x259);
                                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10) + yOffset;
                                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                                *(u8 *)(setup + 4) = 1;
                                Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1,
                                                *(int *)(obj + 0x30));
                            }
                        }
                        break;
                    case 1:
                        range = lbl_803E3BC0;
                        other = ObjGroup_FindNearestObject(0x41, obj, &range);
                        if (other != 0) {
                            otherState = *(LandedArwingState **)(other + 0xb8);
                            if (*(s16 *)(*(int *)(other + 0x4c) + 0x22) > 0) {
                                GameBit_Set(*(s16 *)(*(int *)(other + 0x4c) + 0x22), 1);
                            }
                            otherState->hitFlags = otherState->hitFlags & 0x7f | 0x80;
                        }
                        break;
                }
                state->hitStarted = 0;
                state->hitFlags = state->hitFlags & 0xef | 0x10;
            }
            state->hitFlags = state->hitFlags & 0xbf | 0x40;
            state->path8Fx = lbl_803E3BC4;
        } else {
            if (*(u8 *)(def + 0x1e) == 2) {
                *(s16 *)(obj + 2) = (s16)randomGetRange(-200, 200);
                *(s16 *)(obj + 4) = (s16)randomGetRange(-200, 200);
            }
            ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                      state->hitCooldown);
        }
        ObjAnim_AdvanceCurrentMove(obj, state->path8Fx, timeDelta, animScratch);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* landed arwing material flags: mirrors game bits into the damaged texture state. */
#pragma scheduling off
#pragma peephole off
void landed_arwing_updateDamageTexture(int obj, LandedArwingState *state) {
    int def;
    int *texture;
    u32 bit;
    LandedArwingHitFlagBits *flags;

    def = *(int *)(obj + 0x4c);
    flags = (LandedArwingHitFlagBits *)&state->hitFlags;
    if (*(s16 *)(def + 0x24) != -1) {
        bit = GameBit_Get(*(s16 *)(def + 0x24));
        flags->gameBit24Set = bit;
        bit = flags->gameBit24Set;
        if (bit != 0 && *(u8 *)(def + 0x1c) == 5) {
            flags->impactHandled = 1;
        } else if (bit == 0) {
            flags->impactHandled = 0;
        }
    }

    if (flags->damaged == 0) {
        if (*(s16 *)(def + 0x22) != -1 && GameBit_Get(*(s16 *)(def + 0x22)) != 0) {
            flags->damaged = 1;
        }
    } else {
        if (*(s16 *)(def + 0x22) != -1 && GameBit_Get(*(s16 *)(def + 0x22)) == 0) {
            flags->damaged = 0;
        }
    }

    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
        if (flags->damaged != 0) {
            if (flags->gameBit24Set != 0) {
                *texture = 0x200;
            } else {
                *texture = 0x100;
            }
        } else {
            *texture = 0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int *lbl_803DCAC0;
#define gCarryableInterface lbl_803DCAC0
#pragma scheduling off
#pragma peephole off
void dll_109_init(int obj, u8 *p) {
    *(s16 *)obj = (s16)((s32)p[0x1a] << 8);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
    (*(void (*)(int, int *, int))(*(int *)(*gCarryableInterface + 0x4)))(obj, *(int **)(obj + 0xb8), 0x21);
    (*(void (*)(int *, int))(*(int *)(*gCarryableInterface + 0x2c)))(*(int **)(obj + 0xb8), 1);
}
#pragma peephole reset
#pragma scheduling reset

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void decoration11a_expandBoundsWithVertex(f32 *vertex, f32 *maxOut, f32 *minOut) {
    f32 v;
    v = vertex[0]; if (v > maxOut[0]) maxOut[0] = v; else if (v < minOut[0]) minOut[0] = v;
    v = vertex[1]; if (v > maxOut[1]) maxOut[1] = v; else if (v < minOut[1]) minOut[1] = v;
    v = vertex[2]; if (v > maxOut[2]) maxOut[2] = v; else if (v < minOut[2]) minOut[2] = v;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
int InfoPoint_SeqFn(int obj, int unused, u8 *p3) {
    s16 *inner = *(s16 **)((char *)obj + 0xb8);
    int i;
    for (i = 0; i < p3[0x8b]; i++) {
        switch (p3[0x81 + i]) {
            case 1: inner[0xb] = (s16)0xff; break;
            case 2: inner[0xb] = 0; break;
            case 5: break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int *lbl_803DCAC0;
#pragma scheduling off
void dll_109_free(int obj) {
    (*(void (*)(int))(*(int *)(*gCarryableInterface + 0x10)))(obj);
}
#pragma scheduling reset

extern f32 lbl_803E3B40;
#pragma scheduling off
#pragma peephole off
void dll_109_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xa) == 0) {
        if ((*(int (*)(int, s32))(*(int *)(*gCarryableInterface + 0xc)))(obj, visible) != 0) {
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E3B40);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Obj_SetActiveModelIndex(int *obj, int idx);
extern u32 GameBit_Get(int eventId);
extern f64 lbl_803E3B60;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B58;
extern f32 lbl_803E3B5C;

#pragma scheduling off
#pragma peephole off
void Fall_Ladders_update(int obj) {
    int def;
    FallLaddersState *state;
    f32 speed;

    def = *(int *)(obj + 0x4c);
    state = *(FallLaddersState **)(obj + 0xb8);
    if (*(s16 *)(obj + 0x46) == 0x548) {
        if (GameBit_Get(state->upperGameBit) != 0 && GameBit_Get(state->lowerGameBit) == 0) {
            ((ObjectTriggerUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        }
        if (GameBit_Get(state->upperGameBit) == 0 && GameBit_Get(state->lowerGameBit) != 0) {
            ((ObjectTriggerUpdateFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
        }
    } else if (state->delay != 0) {
        state->delay -= (s32)timeDelta;
        if (state->delay <= 0) {
            state->motionState = 1;
            if (state->playStartSound != 0) {
                Sfx_PlayFromObject(obj, 0x4bc);
                state->playStartSound = 0;
            }
            state->delay = 0;
        }
    } else {
        if ((s8)state->motionState == 0 && GameBit_Get(state->upperGameBit) != 0) {
            state->delay = 10;
        }
        if ((s8)state->motionState == 1 && *(f32 *)(obj + 0x10) >= *(f32 *)(def + 0xc)) {
            *(f32 *)(obj + 0x28) -= lbl_803E3B50;
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
            if (*(f32 *)(obj + 0x10) <= *(f32 *)(def + 0xc)) {
                *(f32 *)(obj + 0x10) = *(f32 *)(def + 0xc);
                *(f32 *)(obj + 0x28) = lbl_803E3B54 * -*(f32 *)(obj + 0x28);
                speed = *(f32 *)(obj + 0x28);
                if (speed < lbl_803E3B58) {
                    speed = -speed;
                }
                if (speed < lbl_803E3B5C) {
                    state->motionState = 2;
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Fall_Ladders_init(int *obj, s8 *def) {
    s16 *state = *(s16 **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s32)*(s8 *)((char *)def + 0x18) << 8);
    state[3] = *(s16 *)((char *)def + 0x20);
    state[2] = *(s16 *)((char *)def + 0x1e);
    *(f32 *)state = (f32)(s32)*(s16 *)((char *)def + 0x1a);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    *(int *)((char *)obj + 0xbc) = (int)return0_80187F30;
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)def + 0xc) + *(f32 *)state;
    Obj_SetActiveModelIndex(obj, (s32)*(s8 *)((char *)def + 0x19));
    *(u8 *)((char *)state + 8) = 0;
    if (GameBit_Get(state[3]) == 0) {
        *(u8 *)((char *)state + 9) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int textureLoadAsset(int id);
extern int *gameTextGet(int id);
extern int lbl_803219A0[];
extern int lbl_80321990[];
#pragma scheduling off
#pragma peephole off
void infopoint_init(int *obj, u8 *def) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    int *txt;
    *(int *)((char *)obj + 0xbc) = (int)InfoPoint_SeqFn;
    if (*(void **)lbl_803219A0 == NULL) {
        *(int *)lbl_803219A0 = textureLoadAsset(616);
    }
    *(int *)(state + 8) = (int)lbl_80321990;
    txt = gameTextGet(*(u16 *)((char *)def + 0x18));
    *(int *)(state + 4) = **(int **)((char *)txt + 8);
    *(int *)(state + 0xc) = 100;
    *(int *)state = (int)txt;
    *(s16 *)obj = (s16)((s32)*(u8 *)((char *)def + 0x1c) << 8);
    *(int *)(state + 0x18) = 2;
    *(u8 *)(state + 0x10) = *(u8 *)((char *)def + 0x1b);
    *(s16 *)(state + 0x16) = 0;
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3B78;
extern f32 lbl_803E3B7C;
extern f64 lbl_803E3B80;
extern f32 lbl_803E3B88;
extern f64 lbl_803E3B90;
extern f32 Vec_distance(f32 *a, f32 *b);
extern void fn_8002B2AC(f32 *out, int obj, f32 *pos);
extern void Model_GetVertexPosition(int *model, int idx, f32 *out);
extern void decoration11a_expandBoundsWithVertex(f32 *vertex, f32 *maxOut, f32 *minOut);
extern void PSVECScale(f32 *dst, f32 *src, f32 s);
extern f32 PSVECMag(f32 *v);

#pragma scheduling off
#pragma peephole off
void decoration11a_hitDetect(int obj) {
    s16 modelId;
    f32 *state;
    int count;
    int *objects;
    f32 radius;
    f32 localPos[3];
    f32 delta;
    f32 xSq;
    f32 ySq;
    f32 zSq;

    modelId = *(s16 *)(obj + 0x46);
    if (modelId == 0x7a1) {
        goto check_decor_objects;
    }
    if (modelId == 0x7a2) {
        goto check_decor_objects;
    }
    if (modelId != 0x7a3) {
        return;
    }

check_decor_objects:
    state = *(f32 **)(obj + 0xb8);
    objects = ObjGroup_GetObjects(2, &count);
    while (count != 0) {
        if (Vec_distance((f32 *)(*objects + 0x18), (f32 *)(obj + 0x18)) < state[6]) {
            if (*(void **)(*objects + 0x54) != NULL) {
                radius = (f32)*(s16 *)(*(int *)(*objects + 0x54) + 0x5a);
                fn_8002B2AC(localPos, obj, (f32 *)(*objects + 0xc));

                if (localPos[0] < state[3]) {
                    delta = localPos[0] - state[3];
                    xSq = delta * delta;
                }
                else if (localPos[0] > state[0]) {
                    delta = localPos[0] - state[0];
                    xSq = delta * delta;
                }
                else {
                    xSq = lbl_803E3B7C;
                }

                if (localPos[1] < state[4]) {
                    delta = localPos[1] - state[4];
                    ySq = delta * delta;
                }
                else if (localPos[1] > state[1]) {
                    delta = localPos[1] - state[1];
                    ySq = delta * delta;
                }
                else {
                    ySq = lbl_803E3B7C;
                }

                if (localPos[2] < state[5]) {
                    delta = localPos[2] - state[5];
                    zSq = delta * delta;
                }
                else if (localPos[2] > state[2]) {
                    delta = localPos[2] - state[2];
                    zSq = delta * delta;
                }
                else {
                    zSq = lbl_803E3B7C;
                }

                if (lbl_803E3B7C + xSq + ySq + zSq < radius * radius) {
                    *(int *)(*(int *)(*objects + 0x54) + 0x50) = obj;
                    *(u8 *)(*(int *)(*objects + 0x54) + 0xad) = 1;
                }
            }
        }
        count--;
        objects++;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void decoration11a_init(int *obj, u8 *def) {
    *(s16 *)((char *)obj + 4) = (s16)((s32)def[24] << 8);
    *(s16 *)((char *)obj + 2) = (s16)((s32)def[25] << 8);
    *(s16 *)obj = (s16)((s32)def[26] << 8);
    if (def[27] != 0) {
        *(f32 *)((char *)obj + 8) = (f32)(u32)def[27] / lbl_803E3B88;
        if (*(f32 *)((char *)obj + 8) == lbl_803E3B7C) {
            *(f32 *)((char *)obj + 8) = lbl_803E3B78;
        }
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * *(f32 *)(*(int *)((char *)obj + 0x50) + 4);
    }
    {
        s16 model = *(s16 *)((char *)obj + 0x46);
        if (model == 1953) {
            goto calc_decor_bounds;
        }
        if (model == 1954) {
            goto calc_decor_bounds;
        }
        if (model == 1955) {
calc_decor_bounds:
        {
            int i;
            int *m;
            f32 *state;
            f32 tmp[3];
            f32 magB;
            f32 maxMag;

            state = *(f32 **)((char *)obj + 0xb8);
            m = **(int ***)(*(int *)((char *)obj + 0x7c));
            Model_GetVertexPosition(m, 0, state);
            Model_GetVertexPosition(m, 0, state + 3);
            for (i = 1; i < *(u16 *)((char *)m + 0xe4); i++) {
                Model_GetVertexPosition(m, i, tmp);
                decoration11a_expandBoundsWithVertex(tmp, state, state + 3);
            }
            PSVECScale(state, state, *(f32 *)((char *)obj + 8));
            PSVECScale(state + 3, state + 3, *(f32 *)((char *)obj + 8));
            magB = PSVECMag(state + 3);
            if (PSVECMag(state) > magB) {
                maxMag = PSVECMag(state);
            } else {
                maxMag = PSVECMag(state + 3);
            }
            state[6] = maxMag;
        }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
