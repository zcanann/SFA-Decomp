#include "ghidra_import.h"
#include "main/dll/ARW/ARWarwingattachment.h"
#include "main/objHitReact.h"
#include "main/objanim.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern uint FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined8 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80053754();
extern int FUN_8005398c();
extern int FUN_800632f4();
extern undefined4 FUN_80135814();
extern uint FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294cc0();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294d6c();

extern undefined4 DAT_802c2bf0;
extern undefined4 DAT_802c2bf4;
extern undefined4 DAT_802c2bf8;
extern undefined4 DAT_802c2bfc;
extern undefined4 DAT_802c2c00;
extern undefined4 DAT_802c2c04;
extern undefined4 DAT_803294d8;
extern undefined4 DAT_803295b4;
extern undefined4 DAT_803295b8;
extern undefined4 DAT_803295bc;
extern undefined4 DAT_803295c0;
extern undefined4 DAT_803295c4;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803de900;
extern f64 DOUBLE_803e69e8;
extern f64 DOUBLE_803e6a38;
extern f64 DOUBLE_803e6a50;
extern f32 lbl_803DC074;
extern f32 lbl_803E699C;
extern f32 lbl_803E69A0;
extern f32 lbl_803E69A8;
extern f32 lbl_803E69AC;
extern f32 lbl_803E69B0;
extern f32 lbl_803E69B4;
extern f32 lbl_803E69C0;
extern f32 lbl_803E69C4;
extern f32 lbl_803E69C8;
extern f32 lbl_803E69CC;
extern f32 lbl_803E69D0;
extern f32 lbl_803E69D4;
extern f32 lbl_803E69D8;
extern f32 lbl_803E69DC;
extern f32 lbl_803E69E0;
extern f32 lbl_803E69F4;
extern f32 lbl_803E69F8;
extern f32 lbl_803E69FC;
extern f32 lbl_803E6A00;
extern f32 lbl_803E6A04;
extern f32 lbl_803E6A08;
extern f32 lbl_803E6A0C;
extern f32 lbl_803E6A10;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A30;
extern f32 lbl_803E6A34;
extern f32 lbl_803E6A40;
extern f32 lbl_803E6A44;
extern f32 lbl_803E6A48;
extern f32 lbl_803E6A4C;
extern f32 lbl_803E6A58;
extern f32 lbl_803E6A64;
extern f32 lbl_803E6A68;
extern f32 lbl_803E6A6C;
extern f32 lbl_803E6A70;
extern f32 lbl_803E6A74;
extern f32 lbl_803E6A78;
extern f32 lbl_803E6A80;

/*
 * --INFO--
 *
 * Function: FUN_801f0b50
 * EN v1.0 Address: 0x801F0B50
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801F0DA4
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0b50(int param_1)
{
  char cVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int local_18 [5];
  
  cVar1 = *(char *)(*(int *)(param_1 + 0x4c) + 0x19);
  if ((((cVar1 != '\b') && (cVar1 < '\b')) && (cVar1 == '\0')) &&
     (((*(int *)(param_1 + 0xf4) == 0 && (uVar4 = FUN_80017690(0xa4), uVar4 == 0)) &&
      (uVar4 = FUN_80017690(0x78), uVar4 == 0)))) {
    piVar5 = ObjGroup_GetObjects(6,local_18);
    bVar2 = false;
    if (0 < local_18[0]) {
      do {
        if (*(short *)(*piVar5 + 0x46) == 0x139) {
          bVar2 = true;
        }
        piVar5 = piVar5 + 1;
        local_18[0] = local_18[0] + -1;
      } while (local_18[0] != 0);
    }
    if (bVar2) {
      if (*(int *)(param_1 + 0xf8) == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        *(undefined4 *)(param_1 + 0xf4) = 1;
        FUN_80017698(0xa4,1);
      }
      else {
        (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
      }
    }
    else {
      *(undefined4 *)(param_1 + 0xf8) = 0x14;
      (**(code **)(*DAT_803dd6cc + 0xc))(0x50,1);
    }
    iVar3 = *(int *)(param_1 + 0xf8) + -1;
    *(int *)(param_1 + 0xf8) = iVar3;
    if (iVar3 < 0) {
      *(undefined4 *)(param_1 + 0xf8) = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0cb8
 * EN v1.0 Address: 0x801F0CB8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801F0F8C
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0cb8(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 9) == '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0cf0
 * EN v1.0 Address: 0x801F0CF0
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801F0FD4
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0cf0(int param_1)
{
  uint uVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(short *)(*(int *)(param_1 + 0xb8) + 6) == 2)) &&
     (uVar1 = FUN_80017690(0x9ad), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
    FUN_80006ba8(0,0x100);
    FUN_80017698(0x9ad,1);
  }
  ObjAnim_AdvanceCurrentMove((double)lbl_803E699C,(double)lbl_803DC074,param_1,
                             (ObjAnimEventList *)0x0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0d8c
 * EN v1.0 Address: 0x801F0D8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1078
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0d8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0d90
 * EN v1.0 Address: 0x801F0D90
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801F112C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0d90(int param_1)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6fc + 0x18))();
  if (*piVar1 != 0) {
    FUN_80053754();
    *piVar1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f0de8
 * EN v1.0 Address: 0x801F0DE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1188
 * EN v1.1 Size: 2376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0de8(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f0dec
 * EN v1.0 Address: 0x801F0DEC
 * EN v1.0 Size: 704b
 * EN v1.1 Address: 0x801F1AD0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f0dec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  int *piVar4;
  undefined8 uVar5;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  uVar5 = ObjMsg_AllocQueue((int)param_9,2);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  if (*(short *)(param_10 + 0x1c) == 0) {
    uVar3 = 0x50;
    uVar1 = FUN_80017760(0xffffffb0,0x50);
    *(short *)(piVar4 + 0xc) = (short)uVar1 + 400;
  }
  else {
    *(short *)(piVar4 + 0xc) = *(short *)(param_10 + 0x1c);
    uVar3 = extraout_r4;
  }
  *(undefined2 *)(piVar4 + 0xb) = *(undefined2 *)(piVar4 + 0xc);
  *(undefined *)((int)piVar4 + 0x4d) = 0;
  piVar4[7] = (int)lbl_803E69A8;
  *(undefined *)((int)piVar4 + 0x4e) = *(undefined *)(param_10 + 0x19);
  *(undefined2 *)((int)piVar4 + 0x2e) = 0x118;
  *(undefined2 *)((int)piVar4 + 0x32) = 0xffff;
  if (*(char *)((int)piVar4 + 0x4e) == '\x1e') {
    if (*piVar4 == 0) {
      iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3e9,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*(char *)((int)piVar4 + 0x4e) == '\x01') {
    if (*piVar4 == 0) {
      iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x23d,uVar3
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      *piVar4 = iVar2;
    }
  }
  else if (*piVar4 == 0) {
    iVar2 = FUN_8005398c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xd9,uVar3,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    *piVar4 = iVar2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f10ac
 * EN v1.0 Address: 0x801F10AC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x801F1BEC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10ac(void)
{
  FUN_80006b0c(DAT_803de900);
  DAT_803de900 = (undefined4*)0x0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f10d8
 * EN v1.0 Address: 0x801F10D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F1C18
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10d8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f10dc
 * EN v1.0 Address: 0x801F10DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F1C70
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f10dc(int param_1)
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
 * Function: FUN_801f1104
 * EN v1.0 Address: 0x801F1104
 * EN v1.0 Size: 1192b
 * EN v1.1 Address: 0x801F1CA4
 * EN v1.1 Size: 1104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1104(void)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  uint uVar5;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int iVar10;
  bool bVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  
  uVar3 = FUN_8028683c();
  iVar4 = FUN_80017a98();
  iVar10 = *(int *)(uVar3 + 0x4c);
  pcVar9 = *(char **)(uVar3 + 0xb8);
  dVar13 = (double)FUN_8001771c((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18));
  dVar12 = (double)lbl_803E69F4;
  *pcVar9 = *pcVar9 + -1;
  if (*pcVar9 < '\0') {
    *pcVar9 = '\0';
    pcVar9[1] = '\0';
  }
  iVar4 = 0;
  pcVar9[6] = pcVar9[6] & 0x7f;
  if ((*(int *)(uVar3 + 0x58) == 0) || (*(char *)(*(int *)(uVar3 + 0x58) + 0x10f) < '\x01')) {
    if ((*(char *)(uVar3 + 0xac) == '\v') &&
       (((cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x03' &&
         (iVar4 = FUN_80017a90(), iVar4 != 0)) &&
        (dVar14 = (double)FUN_8001771c((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18)),
        dVar14 < (double)lbl_803E69FC)))) {
      *pcVar9 = '\x05';
    }
  }
  else {
    *(short *)(pcVar9 + 2) = *(short *)(iVar10 + 0x1e) * 0x3c;
    dVar14 = (double)lbl_803E69F8;
    for (iVar8 = 0; iVar8 < *(char *)(*(int *)(uVar3 + 0x58) + 0x10f); iVar8 = iVar8 + 1) {
      iVar7 = *(int *)(*(int *)(uVar3 + 0x58) + iVar4 + 0x100);
      if (*(short *)(iVar7 + 0x46) == 0x6d) {
        pcVar9[6] = pcVar9[6] & 0x7fU | 0x80;
      }
      if (dVar14 < (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar3 + 0x10))) {
        *pcVar9 = '\x05';
      }
      if (((pcVar9[1] == '\0') && (iVar7 != 0)) && (*(short *)(iVar7 + 0x46) == 0x146)) {
        if (dVar13 <= dVar12) {
          FUN_80006824(uVar3,0x7e);
        }
        pcVar9[1] = '\x01';
      }
      iVar4 = iVar4 + 4;
    }
  }
  if (((*(char *)(uVar3 + 0xac) == '\v') &&
      (cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x01')) && (dVar13 <= dVar12)) {
    if (*pcVar9 == '\0') {
      uVar5 = FUN_80017690(0x905);
      if (uVar5 != 0) {
        FUN_80017698(0x905,0);
      }
    }
    else {
      fVar1 = *(float *)(iVar10 + 0xc) - *(float *)(uVar3 + 0x10);
      if (((fVar1 <= lbl_803E6A00) || (lbl_803E6A04 <= fVar1)) ||
         (uVar5 = FUN_80017690((int)*(short *)(pcVar9 + 4)), uVar5 != 0)) {
        uVar5 = FUN_80017690(0x905);
        if (uVar5 != 0) {
          FUN_80017698(0x905,0);
        }
      }
      else {
        FUN_80017698(0x905,1);
      }
    }
  }
  bVar11 = false;
  if (*pcVar9 == '\0') {
    if (*(short *)(pcVar9 + 2) == 0) {
      *(float *)(uVar3 + 0x10) = lbl_803E6A0C * lbl_803DC074 + *(float *)(uVar3 + 0x10);
      bVar11 = *(float *)(uVar3 + 0x10) <= *(float *)(iVar10 + 0xc);
      if (!bVar11) {
        *(float *)(uVar3 + 0x10) = *(float *)(iVar10 + 0xc);
      }
      FUN_80017698((int)*(short *)(iVar10 + 0x1c),0);
      if (((int)*(short *)(pcVar9 + 4) != 0xffffffff) && (((byte)pcVar9[6] >> 6 & 1) == 0)) {
        FUN_80017698((int)*(short *)(pcVar9 + 4),0);
      }
    }
  }
  else {
    fVar2 = *(float *)(iVar10 + 0xc) - lbl_803E6A04;
    fVar1 = *(float *)(uVar3 + 0x10);
    if (fVar2 <= fVar1) {
      *(float *)(uVar3 + 0x10) = -(lbl_803E6A0C * lbl_803DC074 - fVar1);
      if (fVar2 <= *(float *)(uVar3 + 0x10)) {
        bVar11 = true;
      }
      else {
        *(float *)(uVar3 + 0x10) = fVar2;
        FUN_80017698((int)*(short *)(iVar10 + 0x1c),1);
        if ((int)*(short *)(pcVar9 + 4) != 0xffffffff) {
          FUN_80017698((int)*(short *)(pcVar9 + 4),1);
          if (pcVar9[6] < '\0') {
            pcVar9[6] = pcVar9[6] & 0xbfU | 0x40;
          }
        }
      }
    }
    else {
      *(float *)(uVar3 + 0x10) = lbl_803E6A08 * lbl_803DC074 + fVar1;
      if (fVar2 < *(float *)(uVar3 + 0x10)) {
        *(float *)(uVar3 + 0x10) = fVar2;
      }
      FUN_80017698((int)*(short *)(iVar10 + 0x1c),1);
      if (pcVar9[6] < '\0') {
        FUN_80017698((int)*(short *)(pcVar9 + 4),1);
      }
    }
  }
  if (bVar11) {
    FUN_80006824(uVar3,0x7f);
  }
  else {
    FUN_8000680c(uVar3,8);
  }
  if ((*(short *)(pcVar9 + 2) != 0) &&
     (*(ushort *)(pcVar9 + 2) = *(short *)(pcVar9 + 2) - (ushort)DAT_803dc070,
     *(short *)(pcVar9 + 2) < 0)) {
    pcVar9[2] = '\0';
    pcVar9[3] = '\0';
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f15ac
 * EN v1.0 Address: 0x801F15AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F20F4
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f15ac(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f15b0
 * EN v1.0 Address: 0x801F15B0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801F2228
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f15b0(int param_1)
{
  char in_r8;
  
  if (*(int *)(param_1 + 0xf8) == 0) {
    if (in_r8 == '\0') {
      return;
    }
  }
  else if (in_r8 != -1) {
    return;
  }
  if (*(short *)(*(int *)(param_1 + 0x50) + 0x48) == 2) {
    if (*(short *)(param_1 + 0xb4) == -1) {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) =
           *(uint *)(*(int *)(param_1 + 100) + 0x30) & 0xffffefff;
    }
    else {
      *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 0x1000
      ;
    }
  }
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1634
 * EN v1.0 Address: 0x801F1634
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801F22BC
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1634(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined uVar8;
  float *pfVar6;
  uint uVar7;
  int iVar9;
  float fVar10;
  int iVar11;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar12;
  undefined8 uVar13;
  int local_18 [3];
  
  puVar12 = *(undefined2 **)(param_9 + 0xb8);
  iVar5 = FUN_80017a98();
  if (*(char *)((int)puVar12 + 5) == '\0') {
    uVar8 = 0;
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) && (*(int *)(param_9 + 0xf8) == 0)) {
      *puVar12 = 0;
      puVar12[1] = 0x28;
      FUN_80006ba8(0,0x100);
      uVar8 = 1;
    }
    *(undefined *)((int)puVar12 + 5) = uVar8;
    if (*(char *)((int)puVar12 + 5) != '\0') {
      *(undefined *)(puVar12 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      ObjHits_EnableObject(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      *(float *)(param_9 + 0x28) = -(lbl_803E6A1C * lbl_803DC074 - *(float *)(param_9 + 0x28));
      *(float *)(param_9 + 0x10) =
           *(float *)(param_9 + 0x28) * lbl_803DC074 + *(float *)(param_9 + 0x10);
      iVar5 = FUN_800632f4((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      fVar4 = lbl_803E6A24;
      fVar3 = lbl_803E6A20;
      fVar10 = 0.0;
      iVar11 = 0;
      iVar9 = 0;
      if (0 < iVar5) {
        do {
          pfVar6 = *(float **)(local_18[0] + iVar9);
          if (*(char *)(pfVar6 + 5) != '\x0e') {
            fVar2 = *pfVar6;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               ((fVar2 - fVar3 < *(float *)(param_9 + 0x10) || (iVar11 == 0)))) {
              fVar10 = pfVar6[4];
              *(float *)(param_9 + 0x10) = fVar2;
              *(float *)(param_9 + 0x28) = fVar4;
            }
          }
          iVar9 = iVar9 + 4;
          iVar11 = iVar11 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      if (fVar10 != 0.0) {
        iVar5 = *(int *)((int)fVar10 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    uVar13 = ObjHits_DisableObject(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar7 = FUN_80006c00(0);
    if ((uVar7 & 0x100) != 0) {
      *(undefined *)(puVar12 + 3) = 0;
      uVar13 = FUN_80006ba8(0,0x100);
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar12 + 5) = 2;
    }
    if ((*(char *)((int)puVar12 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) {
      *(undefined *)((int)puVar12 + 5) = 0;
      *(undefined *)(puVar12 + 3) = 0;
    }
    if (*(char *)(puVar12 + 3) != '\0') {
      ObjMsg_SendToObject(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar12[1],*puVar12),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1934
 * EN v1.0 Address: 0x801F1934
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F2568
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1934(int param_1)
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
 * Function: FUN_801f195c
 * EN v1.0 Address: 0x801F195C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801F259C
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f195c(int param_1)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar1 = ObjHits_GetPriorityHit(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar1 != 0) {
    *(undefined *)(psVar3 + 1) = 1;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  if ((*psVar3 < 1) && (*(char *)(psVar3 + 1) != '\0')) {
    uVar2 = FUN_80017690((int)*(short *)(iVar4 + 0x1e));
    if (uVar2 == 0) {
      FUN_80017a78(param_1,1);
      FUN_80017698((int)*(short *)(iVar4 + 0x1e),1);
      FUN_80017698((int)*(short *)(iVar4 + 0x20),1);
    }
    else {
      FUN_80017a78(param_1,0);
      FUN_80017698((int)*(short *)(iVar4 + 0x1e),0);
      FUN_80017698((int)*(short *)(iVar4 + 0x20),0);
    }
    *(undefined *)(psVar3 + 1) = 0;
    *psVar3 = *(short *)(iVar4 + 0x1a);
  }
  else if (0 < *psVar3) {
    *psVar3 = *psVar3 - (ushort)DAT_803dc070;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1a64
 * EN v1.0 Address: 0x801F1A64
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801F26A4
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1a64(int param_1,int param_2)
{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x1e));
  *(char *)(param_1 + 0xad) = (char)uVar1;
  *puVar2 = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(puVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1ac0
 * EN v1.0 Address: 0x801F1AC0
 * EN v1.0 Size: 636b
 * EN v1.1 Address: 0x801F270C
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1ac0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  FUN_80017a98();
  local_28 = DAT_802c2bfc;
  local_24 = DAT_802c2c00;
  local_20 = DAT_802c2c04;
  if ((*(byte *)(param_9 + 0xaf) & 8) != 0) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) ^ 8;
  }
  uVar1 = FUN_80017690(0x2fb);
  if (uVar1 == 0) {
    if (*(short *)(param_9 + 0xa0) != 7) {
      ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,7,0);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                               (double)(float)((double)CONCAT44(0x43300000,uStack_14) -
                                               DOUBLE_803e6a38),param_9,(ObjAnimEventList *)0x0);
  }
  else {
    if (*(short *)(param_9 + 0xa0) != 2) {
      ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,2,0);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                               (double)(float)((double)CONCAT44(0x43300000,uStack_14) -
                                               DOUBLE_803e6a38),param_9,(ObjAnimEventList *)0x0);
  }
  if (((*(byte *)(param_9 + 0xaf) & 1) == 0) || (uVar1 = FUN_80017690(0x2fb), uVar1 != 0)) {
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
       (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_28,3), -1 < iVar2)) {
      FUN_80017698(0x310,1);
      *(char *)(iVar3 + 0x27) = *(char *)(iVar3 + 0x27) + '\x01';
      FUN_80006ba8(0,0x100);
    }
  }
  else {
    FUN_80017698(0x2fb,1);
    *(undefined *)(iVar3 + 0x27) = 0;
    FUN_80006ba8(0,0x100);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f1d3c
 * EN v1.0 Address: 0x801F1D3C
 * EN v1.0 Size: 1668b
 * EN v1.1 Address: 0x801F28C8
 * EN v1.1 Size: 1364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f1d3c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined8 local_50;
  
  pfVar5 = *(float **)(param_9 + 0x5c);
  FUN_80017a98();
  local_78 = DAT_802c2bf0;
  local_74 = DAT_802c2bf4;
  local_70 = DAT_802c2bf8;
  *(float *)(param_9 + 8) = pfVar5[1];
  uVar3 = FUN_80017690(0x1fc);
  if (uVar3 == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
    if (*(short *)(pfVar5 + 8) < 1) {
      uVar3 = FUN_80017760(1,4);
      if (uVar3 == 3) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 3;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 3) {
        if (uVar3 == 1) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 1;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
        else if (0 < (int)uVar3) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 2;
          *(undefined2 *)(pfVar5 + 8) = 400;
        }
      }
      else if (uVar3 == 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 5;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
      else if ((int)uVar3 < 5) {
        *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
        *(undefined *)((int)pfVar5 + 0x22) = 4;
        *(undefined2 *)(pfVar5 + 8) = 400;
      }
    }
    else {
      uVar3 = (uint)*(byte *)((int)pfVar5 + 0x22);
      if (uVar3 == 0xc) {
        dVar7 = (double)*(float *)(&DAT_803295b8 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
        iVar4 = FUN_80017730();
        sVar2 = (short)iVar4 - *param_9;
        FUN_80135814();
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -100;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 100;
          }
        }
        else {
          local_50 = (double)(longlong)
                             (int)*(float *)(&DAT_803295bc +
                                            (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,
                                 (int)*(float *)(&DAT_803295bc +
                                                 (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14),
                                 0);
          pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          *(undefined *)((int)pfVar5 + 0x22) = 0xd;
        }
      }
      else if (uVar3 == 0xd) {
        dVar7 = (double)lbl_803DC074;
        iVar4 = ObjAnim_AdvanceCurrentMove((double)pfVar5[3],dVar7,(int)param_9,
                                           (ObjAnimEventList *)0x0);
        if (iVar4 != 0) {
          local_50 = (double)CONCAT44(0x43300000,(int)param_9[0x50] ^ 0x80000000);
          iVar4 = (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14;
          if ((float)(local_50 - DOUBLE_803e6a50) == *(float *)(&DAT_803295bc + iVar4)) {
            local_50 = (double)(longlong)(int)*(float *)(&DAT_803295c0 + iVar4);
            ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,
                                   (int)*(float *)(&DAT_803295c0 + iVar4),0);
            pfVar5[3] = *(float *)(&DAT_803295c4 + (uint)*(byte *)((int)pfVar5 + 0x23) * 0x14);
          }
        }
        *(ushort *)(pfVar5 + 8) = *(short *)(pfVar5 + 8) - (ushort)DAT_803dc070;
        if (*(short *)(pfVar5 + 8) < 1) {
          *(undefined2 *)(pfVar5 + 8) = 0;
        }
      }
      else {
        dVar9 = (double)(*(float *)(&DAT_803295b4 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 6) - *pfVar5));
        dVar8 = (double)(*(float *)(&DAT_803295b8 + uVar3 * 0x14) -
                        (*(float *)(param_9 + 10) - pfVar5[2]));
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
        dVar7 = dVar8;
        iVar4 = FUN_80017730();
        sVar2 = (short)iVar4 - *param_9;
        if ((sVar2 < -1000) || (1000 < sVar2)) {
          if (param_9[0x50] != 0xc) {
            ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,0xc,0);
            pfVar5[3] = lbl_803E6A48;
          }
          if (sVar2 < 1) {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * -300;
          }
          else {
            *param_9 = *param_9 + (ushort)DAT_803dc070 * 300;
          }
        }
        else {
          if (param_9[0x50] != 0x3b) {
            ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,0x3b,0);
            pfVar5[3] = lbl_803E6A40;
          }
          dVar8 = (double)lbl_803E6A44;
          *(float *)(param_9 + 0x12) = (float)(dVar8 * (double)(float)(dVar9 / dVar6));
          *(float *)(param_9 + 0x16) = (float)(dVar8 * (double)(float)(dVar7 / dVar6));
          ObjAnim_SampleRootCurvePhase(dVar8,(int)param_9,pfVar5 + 3);
        }
        if (dVar6 < (double)lbl_803E6A4C) {
          *(undefined *)((int)pfVar5 + 0x23) = *(undefined *)((int)pfVar5 + 0x22);
          *(undefined *)((int)pfVar5 + 0x22) = 0xc;
          fVar1 = lbl_803E6A30;
          *(float *)(param_9 + 0x12) = lbl_803E6A30;
          *(float *)(param_9 + 0x16) = fVar1;
        }
        *(float *)(param_9 + 6) =
             *(float *)(param_9 + 0x12) * lbl_803DC074 + *(float *)(param_9 + 6);
        *(float *)(param_9 + 10) =
             *(float *)(param_9 + 0x16) * lbl_803DC074 + *(float *)(param_9 + 10);
        ObjAnim_AdvanceCurrentMove((double)pfVar5[3],(double)lbl_803DC074,(int)param_9,
                                   (ObjAnimEventList *)0x0);
      }
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    if (((*(byte *)((int)param_9 + 0xaf) & 1) != 0) &&
       (iVar4 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_78,3), -1 < iVar4)) {
      FUN_80017698(0x4d1,1);
      *(char *)((int)pfVar5 + 0x27) = *(char *)((int)pfVar5 + 0x27) + '\x01';
      FUN_80017698(0x310,1);
      FUN_80006ba8(0,0x100);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f23c0
 * EN v1.0 Address: 0x801F23C0
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x801F2E1C
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f23c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(param_9 + 0xa0) != 2) {
    ObjAnim_SetCurrentMove((double)lbl_803E6A30,(int)param_9,2,0);
  }
  ObjAnim_AdvanceCurrentMove((double)lbl_803E6A34,
                             (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                             DOUBLE_803e6a38),param_9,(ObjAnimEventList *)0x0);
  *(undefined *)(iVar3 + 0x24) = 1;
  if (*(char *)(iVar3 + 0x24) == '\0') {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_80017698(0xd0,1);
      *(undefined *)(iVar3 + 0x24) = 1;
      FUN_80006ba8(0,0x100);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_80017a98();
      iVar1 = FUN_80294d38(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80017690(0xb1);
        if (((uVar2 == 0) || (uVar2 = FUN_80017690(0xb2), uVar2 == 0)) ||
           (uVar2 = FUN_80017690(0xb3), uVar2 == 0)) {
          *(undefined *)(iVar3 + 0x25) = 1;
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
          FUN_80006ba8(0,0x100);
        }
      }
      else {
        *(undefined *)(iVar3 + 0x25) = 2;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
        FUN_80006ba8(0,0x100);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f25b4
 * EN v1.0 Address: 0x801F25B4
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x801F2FAC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f25b4(int param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = FUN_80017a98();
  iVar4 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    cVar1 = *(char *)(iVar4 + 0x25);
    if (cVar1 == '\x01') {
      if (*(char *)(param_3 + iVar3 + 0x81) == '\x04') {
        FUN_80294d40(iVar2,5);
      }
    }
    else if (cVar1 != '\x02') {
      cVar1 = *(char *)(param_3 + iVar3 + 0x81);
      if (cVar1 == '\x01') {
        FUN_80017698(0xd0,1);
        *(undefined *)(iVar4 + 0x24) = 1;
      }
      else if (cVar1 == '\x02') {
        FUN_80294cc0(iVar2,0,1);
        FUN_80294d40(iVar2,5);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f26a8
 * EN v1.0 Address: 0x801F26A8
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x801F30A8
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801f26a8(int param_1,undefined4 param_2,int param_3)
{
  undefined uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  switch(uVar1) {
  case 1:
    FUN_801f25b4(param_1,param_2,param_3);
    break;
  case 4:
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    break;
  case 6:
    iVar2 = *(int *)(param_1 + 0xb8);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      if ((*(char *)(param_3 + iVar3 + 0x81) == '\x01') && (1 < *(byte *)(iVar2 + 0x27))) {
        FUN_80017698(0x314,1);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f284c
 * EN v1.0 Address: 0x801F284C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801F31D8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f284c(void)
{
  int iVar1;
  char cVar3;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
    if (cVar3 == '\x04') {
      uVar2 = FUN_80017690(0x2bd);
      if (uVar2 != 0) {
        FUN_8003b818(iVar1);
      }
    }
    else {
      FUN_8003b818(iVar1);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f28d4
 * EN v1.0 Address: 0x801F28D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F329C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f28d8
 * EN v1.0 Address: 0x801F28D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F33F4
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28d8(undefined2 *param_1,undefined2 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f28dc
 * EN v1.0 Address: 0x801F28DC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F34E4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f28dc(int param_1)
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
 * Function: FUN_801f2904
 * EN v1.0 Address: 0x801F2904
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801F3518
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2904(uint param_1)
{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_1 + 0x4c);
  psVar7 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar7 + 1) = *(char *)(psVar7 + 1) + -1;
  if (*(char *)(psVar7 + 1) < '\0') {
    *(undefined *)(psVar7 + 1) = 0;
  }
  fVar1 = lbl_803E6A64;
  if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
    iVar5 = 0;
    for (iVar6 = 0; iVar6 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar6 = iVar6 + 1) {
      if (fVar1 < *(float *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x10) -
                  *(float *)(param_1 + 0x10)) {
        *(undefined *)(psVar7 + 1) = 0x3c;
      }
      iVar5 = iVar5 + 4;
    }
  }
  bVar3 = false;
  if ((((int)*psVar7 == 0xffffffff) || (uVar4 = FUN_80017690((int)*psVar7), uVar4 != 0)) &&
     (*(char *)(psVar7 + 1) != '\0')) {
    fVar2 = lbl_803E6A68 + lbl_803E6A6C + *(float *)(iVar8 + 0xc);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= fVar2) {
      *(float *)(param_1 + 0x10) = lbl_803E6A74 * lbl_803DC074 + fVar1;
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        bVar3 = true;
      }
      else {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
    else {
      *(float *)(param_1 + 0x10) = -(lbl_803E6A70 * lbl_803DC074 - fVar1);
      if (fVar2 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = -(lbl_803E6A78 * lbl_803DC074 - *(float *)(param_1 + 0x10));
    fVar1 = *(float *)(iVar8 + 0xc);
    if (fVar1 <= *(float *)(param_1 + 0x10)) {
      bVar3 = true;
    }
    else {
      *(float *)(param_1 + 0x10) = fVar1;
    }
  }
  if (bVar3) {
    FUN_80006824(param_1,0x7d);
  }
  else {
    FUN_8000680c(param_1,8);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2ac8
 * EN v1.0 Address: 0x801F2AC8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801F3724
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2ac8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  if ((param_10 == 0) && (**(int **)(param_9 + 0xb8) != 0)) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 **(int **)(param_9 + 0xb8));
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f2b94
 * EN v1.0 Address: 0x801F2B94
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801F37A8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f2b94(short *param_1)
{
  int iVar1;
  double dVar2;
  
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0xc) == '\x02') {
    *param_1 = *param_1 + 0x32;
  }
  iVar1 = FUN_80017a98();
  dVar2 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_1 + 0xc));
  if ((double)lbl_803E6A80 <= dVar2) {
    FUN_8000680c((int)param_1,0x40);
  }
  else {
    FUN_80006824((uint)param_1,0x72);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void pressureswitch_free(void) {}
void pressureswitch_hitDetect(void) {}
void pressureswitch_release(void) {}
void pressureswitch_initialise(void) {}
void fn_801F1BEC(void) {}
void fn_801F1C80(void) {}
void fn_801F1F14(void) {}
void fn_801F1F18(void) {}
void wmlasertarget_free(void) {}
void wmlasertarget_hitDetect(void) {}
void wmlasertarget_release(void) {}
void wmlasertarget_initialise(void) {}
void fn_801F2B9C(void) {}
void fn_801F2C60(void) {}
void fn_801F2E78(void) {}
void fn_801F2E7C(void) {}
void fn_801F2EA8(void) {}
void fn_801F2EDC(void) {}
void fn_801F30D4(void) {}
void fn_801F30D8(void) {}
void fn_801F316C(void) {}
void fn_801F33AC(void) {}
void fn_801F33B0(void) {}
void fn_801F34A8(void) {}

/* 8b "li r3, N; blr" returners. */
int pressureswitch_getExtraSize(void) { return 0x8; }
int pressureswitch_func08(void) { return 0x0; }
int fn_801F1BC8(void) { return 0x8; }
int wmlasertarget_getExtraSize(void) { return 0x4; }
int wmlasertarget_func08(void) { return 0x0; }
int fn_801F2B8C(void) { return 0x28; }
int fn_801F2B94(void) { return 0x1; }
int fn_801F2E98(void) { return 0x4; }
int fn_801F2EA0(void) { return 0x0; }
int fn_801F30DC(void) { return 0x10; }
int fn_801F30E4(void) { return 0x1; }
int fn_801F33B4(void) { return 0x1c; }
int fn_801F33BC(void) { return 0x1; }

/* render-with-fn_8003B8F4 pattern. */
extern f32 lbl_803E5D58;
extern void fn_8003B8F4(f32);
extern f32 lbl_803E5D90;
extern f32 lbl_803E5DC8;
#pragma peephole off
void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5D58); }
void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5D90); }
void fn_801F2EAC(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) fn_8003B8F4(lbl_803E5DC8); }
#pragma peephole reset

/* if (o->_X == K) return A; else return B; */
#pragma peephole off
#pragma scheduling off
#pragma peephole off
int fn_801F1BD0(int *obj) { if (*(s16*)((char*)obj + 0x46) == 0x146) return 0x2; return 0x0; }
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

/* init pattern: short=-1; byte=0; return 0; */
#pragma scheduling off
#pragma peephole off
int fn_801F160C(int p1, int p2, void* p3) { *(s16*)((char*)p3 + 0x6e) = -1; *(u8*)((char*)p3 + 0x56) = 0; return 0; }
int fn_801F2E80(int p1, int p2, void* p3) { *(s16*)((char*)p3 + 0x6e) = -1; *(u8*)((char*)p3 + 0x56) = 0; return 0; }
#pragma peephole reset
#pragma scheduling reset

/* fn_X(lbl); lbl = 0; */
extern u32 lbl_803DDC80;
extern void Resource_Release(u32);
#pragma scheduling off
#pragma peephole off
void fn_801F15B4(void) { Resource_Release(lbl_803DDC80); lbl_803DDC80 = 0; }
#pragma peephole reset
#pragma scheduling reset
