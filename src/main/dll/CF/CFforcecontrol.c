#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/CF/CFforcecontrol.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern undefined4 FUN_80017660();
extern undefined4 FUN_80017688();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern int FUN_800176d0();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_8001792c();
extern undefined4 FUN_80017958();
extern int FUN_80017978();
extern int FUN_80017a54();
extern undefined4 FUN_80017a64();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHits_RecordObjectHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_8005d1e8();
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_80081028();
extern undefined4 FUN_80081030();
extern undefined4 FUN_80081038();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_800d7780();
extern undefined4 FUN_8012f744();
extern char FUN_80132034();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern int FUN_80286830();
extern undefined4 FUN_8028687c();
extern byte FUN_80294c20();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6e8;
extern f64 DOUBLE_803e4910;
extern f64 DOUBLE_803e4950;
extern f64 DOUBLE_803e4998;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e4918;
extern f32 FLOAT_803e491c;
extern f32 FLOAT_803e4920;
extern f32 FLOAT_803e4924;
extern f32 FLOAT_803e4928;
extern f32 FLOAT_803e492c;
extern f32 FLOAT_803e4930;
extern f32 FLOAT_803e4934;
extern f32 FLOAT_803e4938;
extern f32 FLOAT_803e493c;
extern f32 FLOAT_803e4940;
extern f32 FLOAT_803e4944;
extern f32 FLOAT_803e4948;
extern f32 FLOAT_803e494c;
extern f32 FLOAT_803e4960;
extern f32 FLOAT_803e4964;
extern f32 FLOAT_803e4968;
extern f32 FLOAT_803e496c;
extern f32 FLOAT_803e4970;
extern f32 FLOAT_803e4974;
extern f32 FLOAT_803e4978;
extern f32 FLOAT_803e497c;
extern f32 FLOAT_803e4980;
extern f32 FLOAT_803e4984;
extern f32 FLOAT_803e4988;
extern f32 FLOAT_803e498c;
extern f32 FLOAT_803e4990;
extern f32 FLOAT_803e49a0;
extern f32 FLOAT_803e49a4;
extern f32 FLOAT_803e49a8;

/*
 * --INFO--
 *
 * Function: deathgas_free
 * EN v1.0 Address: 0x8018BC50
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8018BC64
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern s16* Camera_GetCurrentViewSlot(void);
extern int* gScreenTransitionInterface;
extern int ObjAnim_SetCurrentMove(int* obj, int moveId, f32 moveProgress, int flags);
extern void setScreenTransitionPause(int v);
extern void fn_8001FE74(int* obj);
extern f32 lbl_803E3D1C;
extern f32 lbl_803E3D58;
extern f32 lbl_803E3D2C;

void deathseq_init(int* obj)
{
  f32* state = *(f32**)((char*)obj + 0xb8);
  s16* cam = Camera_GetCurrentViewSlot();
  f32 f;

  setScreenTransitionPause(1);
  ((void(*)(int,int))((void**)*gScreenTransitionInterface)[2])(1, 1);
  ObjAnim_SetCurrentMove(obj, 0x8e, lbl_803E3D1C, 0);
  state[0] = lbl_803E3D58;
  state[1] = *(f32*)((char*)cam + 0xc);
  state[2] = *(f32*)((char*)cam + 0x10);
  state[3] = *(f32*)((char*)cam + 0x14);
  *(int*)(state + 6) = cam[0];
  *(int*)(state + 7) = cam[1];
  f = lbl_803E3D2C;
  state[4] = f;
  state[5] = f;
  fn_8001FE74(obj);
  *(u16*)((char*)obj + 0xb0) = (u16)(*(u16*)((char*)obj + 0xb0) | 0x400);
}

/*
 * --INFO--
 *
 * Function: FUN_8018bd10
 * EN v1.0 Address: 0x8018BD10
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8018BD34
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bd10(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x1e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bd34
 * EN v1.0 Address: 0x8018BD34
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8018BD5C
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bd34(int param_1)
{
  int iVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_80017a90();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f;
  if ((iVar1 != 0) && (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(), cVar2 != '\0')) {
    dVar5 = (double)FUN_80017710((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
    if (dVar5 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar3 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4910)) {
      *piVar4 = *piVar4 - (uint)DAT_803dc070;
      *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f | 0x80;
    }
  }
  if (*piVar4 == 0) {
    if (iVar1 != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x3c))(iVar1);
      *piVar4 = (uint)*(byte *)(iVar3 + 0x19) * 0x3c;
    }
  }
  else if ((iVar1 != 0) &&
          (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(iVar1), cVar2 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_800400b0();
  }
  GameBit_Set((int)*(short *)(iVar3 + 0x1e),(uint)(*(byte *)(piVar4 + 1) >> 7));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bef8
 * EN v1.0 Address: 0x8018BEF8
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8018BF0C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bef8(short *param_1,int param_2)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  ObjGroup_AddObject((int)param_1,0x1e);
  *piVar1 = (uint)*(byte *)(param_2 + 0x19) * 0x3c;
  *param_1 = (short)*(char *)(param_2 + 0x18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bf58
 * EN v1.0 Address: 0x8018BF58
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x8018BF74
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bf58(int param_1)
{
  int iVar1;
  char cVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar1 = ObjTrigger_IsSet(param_1);
  if ((iVar1 != 0) && (cVar2 = FUN_80132034(), cVar2 == '\0')) {
    *pfVar3 = FLOAT_803e4918;
  }
  if (FLOAT_803e491c < *pfVar3) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar3 = FLOAT_803e491c;
    }
    else {
      *pfVar3 = *pfVar3 - FLOAT_803dc074;
      FUN_8012f744(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) * 2
                    + 0x7c));
    }
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) {
    FUN_800400b0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c00c
 * EN v1.0 Address: 0x8018C00C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8018C038
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c00c(short *param_1,int param_2)
{
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_80017a64((int)param_1,(ushort)*(byte *)(param_2 + 0x19));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c048
 * EN v1.0 Address: 0x8018C048
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x8018C084
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c048(int param_1)
{
  int iVar1;
  byte bVar2;
  char cVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_80017a98();
  if (*(char *)(pfVar4 + 1) == '\0') {
    bVar2 = FUN_80294c20(iVar1);
    if (bVar2 != 0) {
      *(undefined *)(pfVar4 + 1) = 1;
    }
  }
  else {
    bVar2 = FUN_80294c20(iVar1);
    if (bVar2 == 0) {
      *(undefined *)(pfVar4 + 1) = 0;
    }
  }
  FUN_80017a64(param_1,(ushort)*(byte *)(pfVar4 + 1));
  FUN_80017a78(param_1,(uint)*(byte *)(pfVar4 + 1));
  iVar1 = ObjTrigger_IsSet(param_1);
  if ((iVar1 != 0) && (cVar3 = FUN_80132034(), cVar3 == '\0')) {
    *pfVar4 = FLOAT_803e4920;
  }
  if (FLOAT_803e4924 < *pfVar4) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar4 = FLOAT_803e4924;
    }
    else {
      *pfVar4 = *pfVar4 - FLOAT_803dc074;
      FUN_8012f744(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(pfVar4 + 1) * 2 + 0x7c));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c13c
 * EN v1.0 Address: 0x8018C13C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8018C1CC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c13c(int param_1)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar2 + 0xc);
  if (((char)bVar1 < '\0') && ((bVar1 >> 5 & 1) == 0)) {
    FUN_80048000();
  }
  if ((*(byte *)(iVar2 + 0xc) >> 6 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c1a0
 * EN v1.0 Address: 0x8018C1A0
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8018C238
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c1a0(int param_1)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  undefined8 local_18;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
    uVar2 = 1;
  }
  else {
    uVar2 = GameBit_Get((int)*(short *)(iVar6 + 0x1a));
    uVar2 = uVar2 & 0xff;
  }
  if (uVar2 != 0) {
    if (-1 < (char)*(byte *)(pfVar5 + 3)) {
      if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
        FUN_8004800c((double)(FLOAT_803e4928 + *(float *)(param_1 + 0x1c)),
                     (double)(*(float *)(param_1 + 0x1c) - FLOAT_803e492c),(double)FLOAT_803e4930,
                     (double)FLOAT_803e4934,(double)FLOAT_803e4938,0);
      }
      *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f | 0x80;
    }
    iVar3 = FUN_80017a98();
    bVar4 = FUN_80294c20(iVar3);
    if (((bVar4 != 0) || (FLOAT_803e493c + *(float *)(param_1 + 0x1c) < *(float *)(iVar3 + 0x1c)))
       || (dVar7 = (double)FUN_8001771c((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18)),
          (double)pfVar5[2] < dVar7)) {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x19));
        *pfVar5 = *pfVar5 + (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
        if (FLOAT_803e4940 < *pfVar5) {
          (**(code **)(*DAT_803dd6e8 + 100))();
          *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
        }
      }
    }
    else {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
        (**(code **)(*DAT_803dd6e8 + 0x58))(6000,0x603);
        *pfVar5 = FLOAT_803e4940;
        *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf | 0x40;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x18));
      *pfVar5 = *pfVar5 - (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
      fVar1 = FLOAT_803e4948;
      if (*pfVar5 <= FLOAT_803e4948) {
        *pfVar5 = FLOAT_803e4948;
        pfVar5[1] = pfVar5[1] - FLOAT_803dc074;
        if (pfVar5[1] < fVar1) {
          pfVar5[1] = pfVar5[1] + FLOAT_803e494c;
          ObjHits_RecordObjectHit(iVar3,param_1,'\x16',1,0);
        }
      }
    }
    if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*pfVar5);
    }
    return;
  }
  if ((char)*(byte *)(pfVar5 + 3) < '\0') {
    if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
      FUN_80048000();
    }
    *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f;
  }
  if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
    return;
  }
  (**(code **)(*DAT_803dd6e8 + 0x60))();
  *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c4a0
 * EN v1.0 Address: 0x8018C4A0
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8018C5A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c4a0(int param_1)
{
  if (*(char *)(param_1 + 0x37) == -1) {
    FUN_8025cce8(0,1,0,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  gxSetZMode_(1,3,0);
  gxSetPeControl_ZCompLoc_(1);
  FUN_8025c754(7,0,0,7,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c528
 * EN v1.0 Address: 0x8018C528
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8018C630
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c528(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
    uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 8);
    if (uVar1 != 0) {
      FUN_80081038(uVar1);
    }
  }
  if (*(char *)(iVar3 + 0x5c) < '\0') {
    ObjGroup_RemoveObject(param_1,0x4f);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c5b0
 * EN v1.0 Address: 0x8018C5B0
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x8018C6BC
 * EN v1.1 Size: 1040b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c5b0(void)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  byte bVar12;
  undefined uVar13;
  int iVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps30_1;
  double in_ps31_1;
  int local_98;
  float local_94;
  float local_90;
  float local_8c;
  int local_88 [10];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  iVar3 = FUN_80286830();
  iVar14 = *(int *)(iVar3 + 0xb8);
  dVar16 = (double)FLOAT_803e4960;
  local_98 = 0;
  uVar13 = 0x40;
  uVar10 = 0;
  bVar2 = false;
  if ((char)*(byte *)(iVar14 + 0x5c) < '\0') {
    if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0) {
      FUN_800810f4((double)FLOAT_803e4964,(double)FLOAT_803e496c,iVar3,5,1,1,0x14,0,0);
    }
    else {
      FUN_800810f4((double)FLOAT_803e4964,(double)FLOAT_803e4968,iVar3,5,1,1,0x14,0,0);
    }
    piVar4 = (int *)FUN_80017a54(iVar3);
    iVar5 = FUN_8001792c(*piVar4,0);
    *(undefined *)(iVar5 + 0x43) = 0x7f;
    FUN_8003b818(iVar3);
    for (bVar12 = 0; bVar12 < 10; bVar12 = bVar12 + 1) {
      iVar5 = iVar14 + (uint)bVar12 * 4;
      if (*(float **)(iVar5 + 8) == (float *)0x0) {
        if ((!bVar2) && (iVar6 = FUN_800176d0(), iVar6 == 0)) {
          uVar7 = randomGetRange(0,9);
          if ((uVar7 == 0) && ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0)) {
            puVar8 = ObjGroup_GetObjects(0x4f,&local_98);
            for (uVar7 = 0; (int)(uVar7 & 0xff) < local_98; uVar7 = uVar7 + 1) {
              iVar6 = puVar8[uVar7 & 0xff];
              uVar11 = uVar10;
              if (iVar6 != iVar3) {
                if ((*(int *)(iVar6 + 0xb8) == 0) ||
                   ((*(byte *)(*(int *)(iVar6 + 0xb8) + 0x5c) >> 5 & 1) == 0)) {
                  bVar2 = true;
                }
                else {
                  bVar2 = false;
                }
                if ((bVar2) &&
                   (dVar15 = FUN_80017714((float *)(iVar6 + 0x18),(float *)(iVar3 + 0x18)),
                   dVar15 < (double)FLOAT_803e4974)) {
                  uVar11 = uVar10 + 1;
                  local_88[uVar10 & 0xff] = puVar8[uVar7 & 0xff];
                }
              }
              uVar10 = uVar11;
            }
          }
          if ((uVar10 & 0xff) == 0) {
            local_88[0] = iVar3;
          }
          else {
            uVar10 = randomGetRange(0,uVar10 - 1 & 0xff);
            uVar10 = uVar10 & 0xff;
            dVar16 = (double)FUN_8001771c((float *)(local_88[uVar10] + 0x18),(float *)(iVar3 + 0x18)
                                         );
            dVar16 = -(double)(FLOAT_803e4980 * (float)(dVar16 / (double)FLOAT_803e4978) -
                              FLOAT_803e497c);
            uVar13 = 0xff;
          }
          iVar6 = local_88[uVar10 & 0xff];
          local_94 = *(float *)(iVar6 + 0xc);
          local_90 = *(float *)(iVar6 + 0x10);
          local_8c = *(float *)(iVar6 + 0x14);
          if (iVar6 == iVar3) {
            fVar1 = FLOAT_803e4988;
            if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) != 0) {
              fVar1 = FLOAT_803e4984;
            }
            dVar15 = (double)fVar1;
            uVar7 = randomGetRange(0,2000);
            local_94 = (float)(dVar15 * (double)(f32)(s32)(uVar7 - 1000) +
                              (double)local_94);
            uVar7 = randomGetRange(0,2000);
            uStack_54 = uVar7 - 1000 ^ 0x80000000;
            local_58 = 0x43300000;
            local_90 = (float)(dVar15 * (f64)(f32)(s32)uStack_54 + (double)local_90);
            uVar7 = randomGetRange(0,2000);
            uStack_4c = uVar7 - 1000 ^ 0x80000000;
            local_50 = 0x43300000;
            local_8c = (float)(dVar15 * (f64)(f32)(s32)uStack_4c + (double)local_8c);
          }
          uVar9 = FUN_80081030(dVar16,(double)FLOAT_803e498c,iVar3 + 0xc,&local_94,0x14,uVar13,0);
          *(undefined4 *)(iVar5 + 8) = uVar9;
          *(float *)(iVar5 + 0x34) = FLOAT_803e4990;
          bVar2 = true;
        }
      }
      else {
        FUN_80081028(*(float **)(iVar5 + 8));
        iVar6 = FUN_800176d0();
        if (iVar6 == 0) {
          *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x34) + FLOAT_803dc074;
          iVar6 = (int)(FLOAT_803e4970 + *(float *)(iVar5 + 0x34));
          local_60 = (double)(longlong)iVar6;
          *(short *)(*(int *)(iVar5 + 8) + 0x20) = (short)iVar6;
          if (0x14 < *(ushort *)(*(uint *)(iVar5 + 8) + 0x20)) {
            FUN_80081038(*(uint *)(iVar5 + 8));
            *(undefined4 *)(iVar5 + 8) = 0;
          }
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c928
 * EN v1.0 Address: 0x8018C928
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8018CACC
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c928(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined2 *puVar5;
  double dVar6;
  uint uStack_18;
  uint local_14;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  puVar5 = *(undefined2 **)(param_9 + 0xb8);
  iVar2 = FUN_80017a98();
  if ((*(byte *)(puVar5 + 0x2e) >> 6 & 1) == 0) {
    if (((int)*(short *)(iVar4 + 0x1e) == 0xffffffff) ||
       (uVar3 = GameBit_Get((int)*(short *)(iVar4 + 0x1e)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f;
        FUN_800068cc();
        ObjGroup_RemoveObject(param_9,0x4f);
      }
    }
    else if (((int)*(short *)(iVar4 + 0x20) == 0xffffffff) ||
            (uVar3 = GameBit_Get((int)*(short *)(iVar4 + 0x20)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        if ((*(byte *)(puVar5 + 0x2e) >> 4 & 1) != 0) {
          *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
          *(undefined *)(param_9 + 0x36) = 0xff;
          *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xef;
        }
      }
      else {
        FUN_800068d0(param_9,0x403);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f | 0x80;
        ObjGroup_AddObject(param_9,0x4f);
      }
      fVar1 = *(float *)(param_9 + 0x10) - *(float *)(iVar2 + 0x10);
      if ((((FLOAT_803e49a0 < fVar1) && (fVar1 < FLOAT_803e49a4)) &&
          (uVar3 = GameBit_Get(0xe97), uVar3 == 0)) &&
         (dVar6 = FUN_80017708((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18)),
         dVar6 < (double)FLOAT_803e49a8)) {
        *puVar5 = 0xcbe;
        ObjMsg_SendToObject(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x7000a,
                     param_9,(uint)puVar5,in_r7,in_r8,in_r9,in_r10);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf | 0x40;
        GameBit_Set(0xe97,1);
        FUN_80006824(param_9,SFXen_treadlpc);
      }
    }
  }
  else {
    while (iVar2 = ObjMsg_Pop(param_9,&local_14,&uStack_18,(uint *)0x0), iVar2 != 0) {
      if (local_14 == 0x7000b) {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf;
        GameBit_Set((int)*(short *)(iVar4 + 0x1e),1);
        FUN_80017688(0x3f5);
        GameBit_Set(0xe97,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018cbc8
 * EN v1.0 Address: 0x8018CBC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018CD04
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cbc8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018cbcc
 * EN v1.0 Address: 0x8018CBCC
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8018CD64
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cbcc(int param_1)
{
  FUN_800d7780(0);
  FUN_8005d1e8(0);
  FUN_80017660(param_1);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void deathseq_render(void) {}
void deathseq_hitDetect(void) {}
void deathseq_release(void) {}
void deathseq_initialise(void) {}
void dll_127_free_nop(void) {}
void dll_127_hitDetect_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int fuelcell_getExtraSize(void) { return 0x60; }
int deathseq_getExtraSize(void) { return 0x24; }
int deathseq_getObjectTypeId(void) { return 0x0; }
int dll_127_getExtraSize_ret_0(void) { return 0x0; }
int dll_127_getObjectTypeId(void) { return 0x13; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3D60;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3D60); }
#pragma peephole reset

/* Drift-recovery: add new fns with v1.0 names. */
extern void setScreenTransitionPause(int v);
extern void setPendingMapLoad(int v);
extern void deathRenderFn_8001fd98(int* obj);
extern void* Obj_GetActiveModel(int* obj);
extern void ObjModel_SetPostRenderCallback(void* model, void* cb);
extern f32 lbl_803E3CC0;
extern void mm_free_(void *ptr);

typedef struct {
    f32 timer;       // 0x0
    f32 hitTimer;    // 0x4
    f32 radius;      // 0x8
    u8 fogOn : 1;    // 0xc bit 7
    u8 draining : 1; // bit 6
    u8 noFog : 1;    // bit 5
} DeathGasState;

typedef struct {
    u8 pad[0x18];
    u8 drainRate;  // 0x18
    u8 fillRate;   // 0x19
    s16 activeBit; // 0x1a
} DeathGasSetup;

typedef struct {
    u16 msg;          // 0x0
    u8 pad[0x5a];
    u8 lit : 1;       // 0x5c bit 7
    u8 grabbed : 1;   // bit 6
    u8 unkBit5 : 1;   // bit 5
    u8 resetPos : 1;  // bit 4
} FuelcellState;

typedef struct {
    u8 pad[8];
    f32 homeX;   // 0x8
    f32 homeY;   // 0xc
    f32 homeZ;   // 0x10
    u8 pad2[0xa];
    s16 offBit;  // 0x1e
    s16 onBit;   // 0x20
} FuelcellSetup;

#pragma scheduling off
#pragma peephole off

void deathseq_free(int* obj)
{
    setScreenTransitionPause(0);
    setPendingMapLoad(0);
    deathRenderFn_8001fd98(obj);
}

#pragma scheduling off
#pragma peephole off
void deathgas_init(int* obj)
{
    register DeathGasState* state = *(DeathGasState**)((char*)obj + 0xb8);
    *(u16*)((char*)obj + 176) = (u16)(*(u16*)((char*)obj + 176) | 0x4000);
    state->radius = lbl_803E3CC0;
    if (*(s16*)((char*)obj + 0x46) != 2103) return;
    state->noFog = 1;
    state->radius = *(f32*)((char*)obj + 64);
}
#pragma peephole reset
#pragma scheduling reset

int fuelcell_func0B(int* obj)
{
    FuelcellState* state = *(FuelcellState**)((char*)obj + 0xb8);
    state->unkBit5 = 1;
    state->resetPos = 1;
    return 0;
}

void fuelcell_modelMtxFn(u8 *model)
{
    if (model[0x37] == 0xff) {
        GXSetBlendMode(0, 1, 0, 5);
    } else {
        GXSetBlendMode(1, 4, 1, 5);
    }
    gxSetZMode_(1, 3, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
}

void fuelcell_free(int *obj)
{
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    u8 i;

    for (i = 0; i < 10; i++) {
        void *slot = *(void **)(state + 8 + i * 4);
        if (slot != NULL) {
            mm_free_(slot);
        }
    }

    if (((u32)state[0x5c] >> 7) & 1) {
        ObjGroup_RemoveObject(obj, 0x4f);
    }
}

void fuelcell_init(int* obj)
{
    *(void**)((char*)obj + 188) = (void*)fuelcell_func0B;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), (void*)fuelcell_modelMtxFn);
    ObjMsg_AllocQueue(obj, 2);
}

extern void disableHeavyFog(void);
extern int* gGameUIInterface;

void deathgas_free(int* obj)
{
    u8* state = *(u8**)((char*)obj + 0xb8);
    u8 flags = state[12];
    if (((u32)flags >> 7) & 1u) {
        if (!(((u32)flags >> 5) & 1u)) {
            disableHeavyFog();
        }
    }
    if (((u32)state[12] >> 6) & 1u) {
        ((void(*)(void))((void**)*gGameUIInterface)[24])();
    }
}

extern int* Obj_GetPlayerObject(void);
extern int playerIsDisguised(void);
extern f32 Vec_distance(void* a, void* b);
extern void enableHeavyFog(f32 top, f32 bottom, f32 r, f32 g, f32 b, int p6);
extern f32 timeDelta;
extern f32 lbl_803E3C90;
extern f32 lbl_803E3C94;
extern f32 lbl_803E3C98;
extern f32 lbl_803E3C9C;
extern f32 lbl_803E3CA0;
extern f32 lbl_803E3CA4;
extern f32 lbl_803E3CA8;
extern f32 lbl_803E3CAC;
extern f32 lbl_803E3CB0;
extern f32 lbl_803E3CB4;

void deathgas_update(int* obj)
{
    DeathGasSetup* setup = *(DeathGasSetup**)((char*)obj + 0x4c);
    DeathGasState* state = *(DeathGasState**)((char*)obj + 0xb8);
    int* player;
    u8 active;
    int bit;

    bit = setup->activeBit;
    if (bit == -1) {
        active = 1;
    } else {
        active = GameBit_Get(bit);
    }

    if (active == 0) {
        if (state->fogOn) {
            if (!state->noFog) {
                disableHeavyFog();
            }
            state->fogOn = 0;
        }
        if (state->draining) {
            ((void(*)(void))((void**)*gGameUIInterface)[24])();
            state->draining = 0;
        }
        return;
    }

    if (!state->fogOn) {
        if (!state->noFog) {
            enableHeavyFog(lbl_803E3C90 + *(f32*)((char*)obj + 0x1c),
                           *(f32*)((char*)obj + 0x1c) - lbl_803E3C94,
                           lbl_803E3C98, lbl_803E3C9C, lbl_803E3CA0, 0);
        }
        state->fogOn = 1;
    }

    player = Obj_GetPlayerObject();
    if (!playerIsDisguised()
        && *(f32*)((char*)player + 0x1c) <= lbl_803E3CA4 + *(f32*)((char*)obj + 0x1c)
        && Vec_distance((char*)player + 0x18, (char*)obj + 0x18) <= state->radius) {
        if (!state->draining) {
            ((void(*)(int,int))((void**)*gGameUIInterface)[22])(6000, 0x603);
            state->timer = lbl_803E3CA8;
            state->draining = 1;
        }
        state->timer -= (timeDelta * (f32)setup->drainRate) / lbl_803E3CAC;
        if (state->timer <= lbl_803E3CB0) {
            f32 floor = lbl_803E3CB0;
            state->timer = lbl_803E3CB0;
            state->hitTimer -= timeDelta;
            if (state->hitTimer < floor) {
                state->hitTimer += lbl_803E3CB4;
                ObjHits_RecordObjectHit(player, obj, 0x16, 1, 0);
            }
        }
    } else if (state->draining) {
        state->timer += (timeDelta * (f32)setup->fillRate) / lbl_803E3CAC;
        if (state->timer > lbl_803E3CA8) {
            ((void(*)(void))((void**)*gGameUIInterface)[25])();
            state->draining = 0;
        }
    }

    if (state->draining) {
        ((void(*)(int))((void**)*gGameUIInterface)[23])((int)state->timer);
    }
}

extern void gameBitIncrement(int eventId);
extern void Sfx_AddLoopedObjectSound(int* obj, int soundId);
extern void Sfx_RemoveLoopedObjectSound(int* obj, int soundId);
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern f32 getXZDistance(void* a, void* b);
extern f32 lbl_803E3D08;
extern f32 lbl_803E3D0C;
extern f32 lbl_803E3D10;

void fuelcell_update(int* obj)
{
    FuelcellSetup* setup = *(FuelcellSetup**)((char*)obj + 0x4c);
    FuelcellState* state = *(FuelcellState**)((char*)obj + 0xb8);
    int* player;
    int msgId;
    int msgParam;

    player = Obj_GetPlayerObject();
    if (state->grabbed) {
        while (ObjMsg_Pop(obj, &msgId, &msgParam, 0) != 0) {
            if (msgId == 0x7000b) {
                state->grabbed = 0;
                GameBit_Set(setup->offBit, 1);
                gameBitIncrement(0x3f5);
                GameBit_Set(0xe97, 0);
            }
        }
    } else {
        int bit = setup->offBit;
        if (bit != -1 && GameBit_Get(bit) == 0) {
            bit = setup->onBit;
            if (bit == -1 || GameBit_Get(bit) != 0) {
                f32 dy;
                if (!state->lit) {
                    Sfx_AddLoopedObjectSound(obj, 0x403);
                    state->lit = 1;
                    ObjGroup_AddObject(obj, 0x4f);
                } else if (state->resetPos) {
                    *(f32*)((char*)obj + 0xc) = setup->homeX;
                    *(f32*)((char*)obj + 0x10) = setup->homeY;
                    *(f32*)((char*)obj + 0x14) = setup->homeZ;
                    *(u8*)((char*)obj + 0x36) = 0xff;
                    state->resetPos = 0;
                }
                dy = *(f32*)((char*)obj + 0x10) - *(f32*)((char*)player + 0x10);
                if (dy > lbl_803E3D08 && dy < lbl_803E3D0C
                    && GameBit_Get(0xe97) == 0
                    && getXZDistance((char*)obj + 0x18, (char*)player + 0x18) < lbl_803E3D10) {
                    state->msg = 0xcbe;
                    ObjMsg_SendToObject(player, 0x7000a, obj, state);
                    state->grabbed = 1;
                    GameBit_Set(0xe97, 1);
                    Sfx_PlayFromObject(obj, 0x49);
                }
            }
        } else if (state->lit) {
            state->lit = 0;
            Sfx_RemoveLoopedObjectSound(obj, 0x403);
            ObjGroup_RemoveObject(obj, 0x4f);
        }
    }
}

extern void objfx_spawnDirectionalBurst(int* obj, int idx, f32 scale, int b, int c, int d, f32 speed, int e, int f);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void renderFn_8008f904(void* particle);
extern int getHudHiddenFrameCount(void);
extern f32 vec3f_distanceSquared(void* a, void* b);
extern int fn_8008FB20(double radiusX, double radiusY, float* start, float* end, int param_5, int param_6, int param_7);
extern f32 lbl_803E3CC8;
extern f32 lbl_803E3CCC;
extern f32 lbl_803E3CD0;
extern f32 lbl_803E3CD4;
extern f32 lbl_803E3CD8;
extern f32 lbl_803E3CDC;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CE4;
extern f32 lbl_803E3CE8;
extern f32 lbl_803E3CEC;
extern f32 lbl_803E3CF0;
extern f32 lbl_803E3CF4;
extern f32 lbl_803E3CF8;

typedef struct {
    u8 pad0[0xc];
    f32 pos[3];   // 0xc
    f32 pos2[3];  // 0x18
} GameObjPos;

void fuelcell_render(int* obj, int p2, int p3, int p4, int p5)
{
    FuelcellState* state = *(FuelcellState**)((char*)obj + 0xb8);
    int** list;
    u8* slot;
    u8 mode;
    u8 i;
    u8 spawned;
    u8 j;
    u8 pickCount;
    f32 angle;
    f32 scale;
    int* candidates[10];
    f32 pos[3];
    int objCount;

    angle = lbl_803E3CC8;
    objCount = 0;
    mode = 0x40;
    pickCount = 0;
    spawned = 0;
    if (state->lit) {
        if (state->unkBit5) {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3CCC, 1, 1, 0x14, lbl_803E3CD0, 0, 0);
        } else {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3CCC, 1, 1, 0x14, lbl_803E3CD4, 0, 0);
        }
        {
            int op = ObjModel_GetRenderOp(*(int*)Obj_GetActiveModel(obj), 0);
            *(u8*)(op + 0x43) = 0x7f;
        }
        ((void(*)(int*,int,int,int,int,f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3CCC);

        for (i = 0; i < 10; i++) {
            slot = (u8*)state + i * 4;
            if (*(void**)(slot + 8) != NULL) {
                renderFn_8008f904(*(void**)(slot + 8));
                if (getHudHiddenFrameCount() == 0) {
                    *(f32*)(slot + 0x34) += timeDelta;
                    *(u16*)(*(char**)(slot + 8) + 0x20) = (int)(lbl_803E3CD8 + *(f32*)(slot + 0x34));
                    if (*(u16*)(*(char**)(slot + 8) + 0x20) > 0x14) {
                        mm_free_(*(void**)(slot + 8));
                        *(void**)(slot + 8) = NULL;
                    }
                }
            } else if (!spawned && getHudHiddenFrameCount() == 0) {
                int* target;
                if ((int)randomGetRange(0, 9) == 0 && !state->unkBit5) {
                    list = (int**)ObjGroup_GetObjects(0x4f, &objCount);
                    for (j = 0; (int)j < objCount; j++) {
                        int ofs = j * 4;
                        int* other = *(int**)((char*)list + ofs);
                        u8 ok;
                        if (other != obj) {
                            FuelcellState* ost = *(FuelcellState**)((char*)other + 0xb8);
                            if (ost != NULL && ost->unkBit5) {
                                ok = 0;
                            } else {
                                ok = 1;
                            }
                            if (ok && vec3f_distanceSquared(((GameObjPos*)other)->pos2, ((GameObjPos*)obj)->pos2) < lbl_803E3CDC) {
                                candidates[pickCount++] = *(int**)((char*)list + ofs);
                            }
                        }
                    }
                }
                if (pickCount != 0) {
                    pickCount = randomGetRange(0, (u8)(pickCount - 1));
                    angle = -(lbl_803E3CE8 * (Vec_distance(((GameObjPos*)candidates[pickCount])->pos2, ((GameObjPos*)obj)->pos2) / lbl_803E3CE0) - lbl_803E3CE4);
                    mode = 0xff;
                } else {
                    candidates[0] = obj;
                }
                target = candidates[pickCount];
                pos[0] = *(f32*)((char*)target + 0xc);
                pos[1] = *(f32*)((char*)target + 0x10);
                pos[2] = *(f32*)((char*)target + 0x14);
                if (target == obj) {
                    if (state->unkBit5) {
                        scale = lbl_803E3CEC;
                    } else {
                        scale = lbl_803E3CF0;
                    }
                    pos[0] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[0];
                    pos[1] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[1];
                    pos[2] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[2];
                }
                *(int*)(slot + 8) = fn_8008FB20(angle, lbl_803E3CF4, ((GameObjPos*)obj)->pos, pos, 0x14, mode, 0);
                *(f32*)(slot + 0x34) = lbl_803E3CF8;
                spawned = 1;
            }
        }
    }
}

typedef struct {
    f32 timer;                 // 0x0
    f32 camX;                  // 0x4
    f32 camY;                  // 0x8
    f32 camZ;                  // 0xc
    f32 dist;                  // 0x10
    f32 distTarget;            // 0x14
    int camRotY;               // 0x18
    int camRotX;               // 0x1c
    u8 menuShown : 1;          // 0x20 bit 7
    u8 camActive : 1;          // bit 6
    u8 transitionStarted : 1;  // bit 5
} DeathSeqState;

extern int fn_80296C5C(void);
extern void fn_80296C6C(int* player, int v);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int streamId, void* cb);
extern int ObjAnim_AdvanceCurrentMove(int* obj, f32 speed, f32 dt, int flags);
extern int* objFindTexture(int* obj, int idx, int p3);
extern void cutsceneFadeInOut(int v);
extern void Obj_FreeObject(int* obj);
extern void showDeathMenu(void);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void Camera_SetFovY(f32 fov);
extern void Rcp_SetViewFinderHudEnabled(int v);
extern f32 lbl_803E3D18;
extern f32 lbl_803E3D20;
extern f32 lbl_803E3D24;
extern f32 lbl_803E3D28;
extern f32 lbl_803E3D30;
extern f32 lbl_803E3D34;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D40;
extern f32 lbl_803E3D44;
extern f32 lbl_803E3D48;

void deathseq_update(int* obj)
{
    s16* cam = Camera_GetCurrentViewSlot();
    DeathSeqState* state = *(DeathSeqState**)((char*)obj + 0xb8);
    int ready;
    int* player = Obj_GetPlayerObject();
    int* tex;

    ready = 0;
    if (fn_80296C5C() != 0) {
        state->distTarget = lbl_803E3D18;
        if (*(s16*)((char*)obj + 0xa0) != 0x92) {
            AudioStream_StopCurrent();
            AudioStream_Play(0x51e1, (void*)AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove(obj, 0x92, lbl_803E3D1C, 0);
        }
        ObjAnim_AdvanceCurrentMove(obj, lbl_803E3D20, timeDelta, 0);
        if (*(f32*)((char*)obj + 0x98) > lbl_803E3D24) {
            tex = objFindTexture(obj, 5, 0);
            *tex = 0;
            tex = objFindTexture(obj, 4, 0);
            *tex = 0;
        }
        if (*(f32*)((char*)obj + 0x98) >= lbl_803E3D28) {
            if (!state->transitionStarted) {
                setScreenTransitionPause(0);
                ((void(*)(int,int))((void**)*gScreenTransitionInterface)[3])(10, 1);
                state->transitionStarted = 1;
            }
            if (((int(*)(void))((void**)*gScreenTransitionInterface)[5])() != 0) {
                if (player != NULL) {
                    fn_80296C6C(player, 0);
                }
                cutsceneFadeInOut(0);
                setPendingMapLoad(0);
                Obj_FreeObject(obj);
            }
        } else {
            ready = 1;
        }
    } else {
        state->distTarget = lbl_803E3D2C;
        if (((int(*)(void))((void**)*gScreenTransitionInterface)[5])() != 0) {
            ObjAnim_AdvanceCurrentMove(obj, lbl_803E3D20, timeDelta, 0);
            ready = 1;
        }
        if (*(f32*)((char*)obj + 0x98) > lbl_803E3D24) {
            tex = objFindTexture(obj, 5, 0);
            *tex = 0x200;
            tex = objFindTexture(obj, 4, 0);
            *tex = 0x200;
        }
        state->timer -= timeDelta;
        if (state->timer <= lbl_803E3D1C) {
            state->timer = lbl_803E3D1C;
            if (!state->menuShown) {
                showDeathMenu();
                state->menuShown = 1;
            }
        }
    }

    if (ready != 0) {
        f32 cos30 = fn_80293E80(lbl_803E3D30);
        f32 sin30 = sin(lbl_803E3D30);
        f32 sin34 = sin(lbl_803E3D34);
        f32 cos34 = fn_80293E80(lbl_803E3D34);
        f32 xTerm;
        f32 negSin;
        f32 fz;
        f32 zTerm;
        f32 dz = state->dist * cos34;
        sin34 = state->dist * sin34;
        sin30 = sin34 * sin30;
        sin34 = sin34 * cos30;
        cam[0] = 0x2000;
        cam[1] = 0x1000;
        xTerm = lbl_803E3D38 * -fn_80293E80((lbl_803E3D3C * (f32)*(s16*)obj) / lbl_803E3D40);
        negSin = -sin((lbl_803E3D3C * (f32)*(s16*)obj) / lbl_803E3D40);
        fz = lbl_803E3D38;
        zTerm = fz * negSin;
        *(f32*)((char*)cam + 0xc) = sin30 + (*(f32*)((char*)obj + 0x18) + xTerm);
        *(f32*)((char*)cam + 0x10) = (fz + *(f32*)((char*)obj + 0x1c)) + dz;
        *(f32*)((char*)cam + 0x14) = sin34 + (*(f32*)((char*)obj + 0x20) + zTerm);
        Camera_SetFovY(lbl_803E3D44);
        state->camActive = 1;
        state->dist += interpolate(state->distTarget - state->dist, lbl_803E3D48, timeDelta);
        Rcp_SetViewFinderHudEnabled(0);
    } else {
        cam[0] = state->camRotY;
        cam[1] = state->camRotX;
        *(f32*)((char*)cam + 0xc) = state->camX;
        *(f32*)((char*)cam + 0x10) = state->camY;
        *(f32*)((char*)cam + 0x14) = state->camZ;
        state->camActive = 0;
    }

    if (state->camActive) {
        *(s16*)((char*)obj + 6) = *(s16*)((char*)obj + 6) & ~0x4000;
    } else {
        *(s16*)((char*)obj + 6) = *(s16*)((char*)obj + 6) | 0x4000;
    }
}

#pragma peephole reset
#pragma scheduling reset
