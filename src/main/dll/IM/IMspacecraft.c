#include "ghidra_import.h"
#include "main/dll/IM/IMspacecraft.h"

extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_8000691c();
extern int FUN_80006a10();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017520();
extern uint FUN_80017524();
extern undefined4 FUN_800175d0();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017a40();
extern undefined4 FUN_80017a44();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80035b84();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_801a5230();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80286838();
extern undefined4 FUN_80286884();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2a78;
extern undefined4 DAT_802c2a7c;
extern undefined4 DAT_802c2a80;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb38;
extern undefined4 DAT_803dcb3c;
extern undefined4 DAT_803dcb40;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de7a0;
extern f64 DOUBLE_803e50a8;
extern f64 DOUBLE_803e50d0;
extern f64 DOUBLE_803e5120;
extern f64 DOUBLE_803e5128;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e5088;
extern f32 FLOAT_803e508c;
extern f32 FLOAT_803e50b0;
extern f32 FLOAT_803e50b4;
extern f32 FLOAT_803e50b8;
extern f32 FLOAT_803e50bc;
extern f32 FLOAT_803e50c0;
extern f32 FLOAT_803e50c8;
extern f32 FLOAT_803e50d8;
extern f32 FLOAT_803e50dc;
extern f32 FLOAT_803e50e0;
extern f32 FLOAT_803e50e4;
extern f32 FLOAT_803e50e8;
extern f32 FLOAT_803e50ec;
extern f32 FLOAT_803e50f0;
extern f32 FLOAT_803e5100;
extern f32 FLOAT_803e5104;
extern f32 FLOAT_803e5108;
extern f32 FLOAT_803e510c;
extern f32 FLOAT_803e5110;
extern f32 FLOAT_803e5114;
extern f32 FLOAT_803e5118;
extern f32 FLOAT_803e511c;
extern f32 FLOAT_803e5130;
extern f32 FLOAT_803e5134;
extern f32 FLOAT_803e5138;
extern f32 FLOAT_803e513c;
extern f32 FLOAT_803e5140;
extern f32 FLOAT_803e5144;
extern f32 FLOAT_803e5148;
extern f32 FLOAT_803e514c;

/*
 * --INFO--
 *
 * Function: FUN_801a57e8
 * EN v1.0 Address: 0x801A57E8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A5818
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a57e8(int param_1)
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
 * Function: FUN_801a5810
 * EN v1.0 Address: 0x801A5810
 * EN v1.0 Size: 860b
 * EN v1.1 Address: 0x801A584C
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801a5810(ushort *param_1,float *param_2)
{
  int iVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  dVar5 = (double)FLOAT_803e5088;
  FUN_80017a44(param_1,param_2,&local_68,'\0');
  *(float *)(param_1 + 0x12) = FLOAT_803dc074 * param_2[0xc] + *(float *)(param_1 + 0x12);
  *(float *)(param_1 + 0x14) = FLOAT_803dc074 * param_2[0xd] + *(float *)(param_1 + 0x14);
  *(float *)(param_1 + 0x16) = FLOAT_803dc074 * param_2[0xe] + *(float *)(param_1 + 0x16);
  param_2[6] = FLOAT_803dc074 * param_2[9] + param_2[6];
  param_2[7] = FLOAT_803dc074 * param_2[10] + param_2[7];
  param_2[8] = FLOAT_803dc074 * param_2[0xb] + param_2[8];
  fVar3 = FLOAT_803e5088;
  if (param_2[0x15] <= local_64) {
    *(byte *)((int)param_2 + 0x66) = *(byte *)((int)param_2 + 0x66) & 0xfb;
  }
  else {
    if (((*(float *)(param_1 + 0x14) < FLOAT_803e5088) &&
        ((*(byte *)((int)param_2 + 0x66) & 4) != 0)) ||
       (FLOAT_803e5088 == *(float *)(param_1 + 0x14))) {
      param_2[0xd] = FLOAT_803e5088;
      param_2[0xb] = fVar3;
      param_2[8] = fVar3;
      param_2[10] = fVar3;
      param_2[7] = fVar3;
      param_2[9] = fVar3;
      param_2[6] = fVar3;
      *(float *)(param_1 + 0x14) = fVar3;
      fVar2 = FLOAT_803e50b0;
      param_2[0xc] = param_2[0xc] * FLOAT_803e50b0;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * fVar2;
      param_2[0xe] = param_2[0xe] * fVar2;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
      fVar2 = *(float *)(param_1 + 0x12);
      if (fVar2 < fVar3) {
        fVar2 = -fVar2;
      }
      if (fVar2 < FLOAT_803e50b4) {
        fVar3 = *(float *)(param_1 + 0x16);
        if (fVar3 < FLOAT_803e5088) {
          fVar3 = -fVar3;
        }
        if (fVar3 < FLOAT_803e50b4) {
          dVar5 = (double)FLOAT_803e508c;
        }
      }
    }
    if (*(float *)(param_1 + 0x14) < FLOAT_803e5088) {
      *(float *)(param_1 + 0x14) = FLOAT_803e50b8 * -*(float *)(param_1 + 0x14);
      fVar3 = FLOAT_803e50b0;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e50b0;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
      param_2[0xd] = FLOAT_803e50bc;
      param_2[0xb] = -param_2[0xb];
    }
    *(byte *)((int)param_2 + 0x66) = *(byte *)((int)param_2 + 0x66) | 4;
  }
  dVar4 = DOUBLE_803e50a8;
  uStack_4c = (int)(short)*param_1 ^ 0x80000000;
  local_50 = 0x43300000;
  iVar1 = (int)(param_2[6] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e50a8));
  local_48 = (longlong)iVar1;
  *param_1 = (ushort)iVar1;
  uStack_3c = (int)(short)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)(param_2[7] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4));
  local_38 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  uStack_2c = (int)(short)param_1[2] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar1 = (int)(param_2[8] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4));
  local_28 = (longlong)iVar1;
  param_1[2] = (ushort)iVar1;
  FUN_80017a44(param_1,param_2,&local_5c,'\0');
  *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + (local_68 - local_5c);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + (local_64 - local_58);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 10) + (local_60 - local_54);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  return (int)dVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5b6c
 * EN v1.0 Address: 0x801A5B6C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x801A5BCC
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5b6c(ushort *param_1)
{
  bool bVar1;
  uint uVar2;
  int iVar3;
  float fVar4;
  float *pfVar5;
  
  pfVar5 = *(float **)(param_1 + 0x5c);
  if ((*(char *)((int)pfVar5 + 0x69) == '\x01') &&
     (iVar3 = FUN_801a5810(param_1,pfVar5), iVar3 != 0)) {
    *(undefined *)((int)pfVar5 + 0x69) = 0;
  }
  if (pfVar5[0x17] != -NAN) {
    fVar4 = pfVar5[0x16];
    uVar2 = (uint)DAT_803dc070;
    pfVar5[0x16] = (float)((int)fVar4 + uVar2);
    if ((int)pfVar5[0x17] <= (int)((int)fVar4 + uVar2)) {
      pfVar5[0x17] = -NAN;
      *(undefined *)(param_1 + 0x1b) = 0;
      param_1[3] = param_1[3] | 0x4000;
      bVar1 = true;
      goto LAB_801a5c8c;
    }
    iVar3 = (int)pfVar5[0x17] - (int)pfVar5[0x16];
    if (iVar3 < 0xff) {
      *(char *)(param_1 + 0x1b) = (char)iVar3;
    }
  }
  bVar1 = false;
LAB_801a5c8c:
  if (bVar1) {
    *(undefined *)((int)pfVar5 + 0x69) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5c74
 * EN v1.0 Address: 0x801A5C74
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x801A5CB4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5c74(int param_1,int param_2,int param_3)
{
  float *pfVar1;
  
  *(undefined *)(param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  pfVar1 = *(float **)(param_1 + 0xb8);
  *(float *)(param_1 + 8) =
       (*(float *)(*(int *)(param_1 + 0x50) + 4) *
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x3d) ^ 0x80000000) -
              DOUBLE_803e50a8)) / FLOAT_803e50c0;
  FUN_801a5230(param_1,param_2,param_3,pfVar1);
  if ((((*(short *)(param_2 + 0x20) == 0) && (*(short *)(param_2 + 0x22) == 0)) &&
      (*(short *)(param_2 + 0x24) == 0)) &&
     (((*(short *)(param_2 + 0x26) == 0 && (*(short *)(param_2 + 0x28) == 0)) &&
      (*(short *)(param_2 + 0x2a) == 0)))) {
    *(undefined *)((int)pfVar1 + 0x69) = 0;
  }
  else {
    *(undefined *)((int)pfVar1 + 0x69) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5d74
 * EN v1.0 Address: 0x801A5D74
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x801A5DAC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5d74(int param_1)
{
  if (**(uint **)(param_1 + 0xb8) != 0) {
    FUN_80017520(*(uint **)(param_1 + 0xb8));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a5da4
 * EN v1.0 Address: 0x801A5DA4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801A5DDC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5da4(int param_1)
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
 * Function: FUN_801a5dcc
 * EN v1.0 Address: 0x801A5DCC
 * EN v1.0 Size: 1176b
 * EN v1.1 Address: 0x801A5E10
 * EN v1.1 Size: 1044b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a5dcc(void)
{
  ushort uVar1;
  ushort *puVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  uint *puVar7;
  double dVar8;
  double dVar9;
  double in_f31;
  double in_ps31_1;
  int local_68;
  float afStack_64 [3];
  float local_58;
  float local_54;
  undefined4 local_50;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar2 = (ushort *)FUN_80286838();
  local_58 = DAT_802c2a78;
  local_54 = DAT_802c2a7c;
  local_50 = DAT_802c2a80;
  puVar7 = *(uint **)(puVar2 + 0x5c);
  iVar6 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_80017a98();
  uVar4 = FUN_80017690(0xab9);
  if ((uVar4 == 0) &&
     (dVar8 = (double)FUN_80017710((float *)(puVar2 + 0xc),(float *)(iVar3 + 0x18)),
     dVar8 < (double)FLOAT_803e50dc)) {
    if (puVar7[2] != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,puVar2,0xffffffff);
    }
    FUN_80017698(0xab9,1);
  }
  if (puVar7[2] == 0) {
    uVar4 = FUN_80017690((int)*(short *)(iVar6 + 0x1e));
    if (uVar4 == 0) {
      uVar4 = FUN_80017690((int)*(short *)(iVar6 + 0x20));
      puVar7[2] = uVar4;
      if (puVar7[2] != 0) {
        local_48 = (double)CONCAT44(0x43300000,(int)*(char *)(iVar6 + 0x19) ^ 0x80000000);
        *(float *)(puVar2 + 4) =
             *(float *)(*(int *)(puVar2 + 0x28) + 4) * (float)(local_48 - DOUBLE_803e50d0) *
             FLOAT_803e50e0;
        if (*puVar7 == 0) {
          uVar4 = FUN_80017524(puVar2,0xff,0,0x4d,0);
          *puVar7 = uVar4;
        }
      }
    }
    else {
      if (*(char *)(puVar2 + 0x1b) == -1) {
        FUN_80006824(0,0x109);
      }
      if (*(char *)(puVar2 + 0x1b) == '\0') {
        if (*puVar7 != 0) {
          FUN_80017520(puVar7);
        }
      }
      else {
        *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + -1;
        if (*puVar7 != 0) {
          local_48 = (double)CONCAT44(0x43300000,*(byte *)(puVar2 + 0x1b) >> 2 ^ 0x80000000);
          uStack_3c = (*(byte *)(puVar2 + 0x1b) >> 2) + 10 ^ 0x80000000;
          local_40 = 0x43300000;
          FUN_800175d0((double)(float)(local_48 - DOUBLE_803e50d0),
                       (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50d0),
                       *puVar7);
        }
        *(float *)(puVar2 + 4) = *(float *)(puVar2 + 4) * FLOAT_803e50e4;
        uStack_3c = (int)(short)puVar2[2] ^ 0x80000000;
        local_40 = 0x43300000;
        iVar3 = (int)-(FLOAT_803e50e8 * FLOAT_803dc074 -
                      (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50d0));
        local_48 = (double)(longlong)iVar3;
        puVar2[2] = (ushort)iVar3;
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar3 != 0x51) {
      FUN_800068c4((uint)puVar2,0x423);
    }
    piVar5 = ObjGroup_GetObjects(0x4e,&local_68);
    uVar4 = puVar7[3];
    uVar1 = (ushort)puVar7[1];
    local_54 = FLOAT_803e50ec;
    dVar8 = (double)FLOAT_803e50f0;
    for (iVar3 = 0; iVar3 < local_68; iVar3 = iVar3 + 1) {
      dVar9 = (double)FUN_8001771c((float *)(puVar2 + 0xc),(float *)(*piVar5 + 0x18));
      if (dVar9 <= dVar8) {
        puVar2[2] = uVar1;
        FUN_80017a40(puVar2,&local_58,afStack_64);
        FUN_80247e94((float *)(puVar2 + 6),afStack_64,(float *)(*piVar5 + 0xc));
        *(ushort *)*piVar5 = *puVar2;
        *(ushort *)(*piVar5 + 4) = uVar1 + 0x8000;
        *(undefined4 *)(*piVar5 + 8) = *(undefined4 *)(puVar2 + 4);
        uVar1 = uVar1 + (short)(0x10000 / (int)uVar4);
      }
      piVar5 = piVar5 + 1;
    }
    puVar7[1] = puVar7[1] + (int)DAT_803dcb38;
    puVar2[2] = 0;
    if (local_68 == 0) {
      puVar7[2] = 0;
      FUN_80017698((int)*(short *)(iVar6 + 0x1e),1);
      ObjHits_DisableObject((int)puVar2);
    }
    iVar3 = FUN_80039520((int)puVar2,0);
    if (iVar3 != 0) {
      *(ushort *)(iVar3 + 10) = *(short *)(iVar3 + 10) + (short)DAT_803dcb3c * (ushort)DAT_803dc070;
      *(ushort *)(iVar3 + 8) = *(short *)(iVar3 + 8) + (short)DAT_803dcb3c * (ushort)DAT_803dc070;
      if (DAT_803dcb40 << 8 < (int)*(short *)(iVar3 + 10)) {
        *(short *)(iVar3 + 10) = *(short *)(iVar3 + 10) - (short)(DAT_803dcb40 << 8);
      }
      if (DAT_803dcb40 << 8 < (int)*(short *)(iVar3 + 8)) {
        *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) - (short)(DAT_803dcb40 << 8);
      }
    }
    if (*(char *)(puVar2 + 0x1b) != -1) {
      *(char *)(puVar2 + 0x1b) = *(char *)(puVar2 + 0x1b) + '\x01';
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6264
 * EN v1.0 Address: 0x801A6264
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x801A6224
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6264(undefined2 *param_1,int param_2,int param_3)
{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  puVar4[3] = (int)*(short *)(param_2 + 0x1a);
  puVar4[2] = 0;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                 DOUBLE_803e50d0) * FLOAT_803e50e0;
  uVar2 = countLeadingZeros(((uint)(byte)((fVar1 == FLOAT_803e50c8) << 1) << 0x1c) >> 0x1d ^ 1);
  if (uVar2 >> 5 != 0) {
    fVar1 = FLOAT_803e50d8;
  }
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  puVar4[1] = 0;
  ObjHits_DisableObject((int)param_1);
  *(byte *)(puVar4 + 4) = *(byte *)(puVar4 + 4) & 0x7f;
  if (param_3 == 0) {
    *(undefined *)(param_1 + 0x1b) = 0;
    uVar3 = FUN_80017524(param_1,0xff,0,0x4d,0);
    *puVar4 = uVar3;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a6378
 * EN v1.0 Address: 0x801A6378
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x801A633C
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a6378(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  DAT_803de7a0 = DAT_803de7a0 + 1;
  FUN_80006824(param_9,0x106);
  if (DAT_803de7a0 < 2) {
    uVar1 = FUN_80017760(0,1);
    uVar2 = FUN_80017760(0x32,0x3c);
    FUN_8008112c((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5120),
                 param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,
                 0,1,0);
  }
  else {
    uVar1 = FUN_80017760(0,1);
    uVar2 = FUN_80017760(0x32,0x3c);
    FUN_8008112c((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5120),
                 param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,0,uVar1 & 0xff,
                 0,0,0);
  }
  *(undefined *)(iVar3 + 0x114) = 1;
  *(float *)(iVar3 + 0x110) = FLOAT_803e5100;
  *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
  FUN_80035b84(param_9,(short)(int)(FLOAT_803e5104 *
                                   (float)((double)CONCAT44(0x43300000,
                                                            (uint)*(byte *)(*(int *)(param_9 + 0x50)
                                                                           + 0x62)) -
                                          DOUBLE_803e5128)));
  iVar3 = FUN_80017a98();
  if ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) {
    dVar4 = (double)FUN_8001771c((float *)(param_9 + 0x18),(float *)(iVar3 + 0x18));
    if (dVar4 <= (double)FLOAT_803e5108) {
      dVar4 = (double)(FLOAT_803e510c - (float)(dVar4 / (double)FLOAT_803e5108));
      FUN_8000691c((double)(float)((double)FLOAT_803e5110 * dVar4),
                   (double)(float)((double)FLOAT_803e5114 * dVar4),(double)FLOAT_803e5118);
      FUN_80006b94((double)(float)((double)FLOAT_803e511c * dVar4));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a662c
 * EN v1.0 Address: 0x801A662C
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801A6534
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a662c(int param_1)
{
  int *piVar1;
  int iVar2;
  int local_18 [4];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  piVar1 = ObjGroup_GetObjects(0x2f,local_18);
  if (0 < local_18[0]) {
    do {
      if (*piVar1 == param_1) {
        ObjGroup_RemoveObject(param_1,0x2f);
        break;
      }
      piVar1 = piVar1 + 1;
      local_18[0] = local_18[0] + -1;
    } while (local_18[0] != 0);
  }
  if (*(char *)(iVar2 + 0x114) == '\x01') {
    DAT_803de7a0 = DAT_803de7a0 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a66c0
 * EN v1.0 Address: 0x801A66C0
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801A65C0
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a66c0(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (*(char *)(*(int *)(param_1 + 0xb8) + 0x114) == '\0')) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a66f8
 * EN v1.0 Address: 0x801A66F8
 * EN v1.0 Size: 1912b
 * EN v1.1 Address: 0x801A6608
 * EN v1.1 Size: 1224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a66f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  float *pfVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  uint uStack_48;
  int iStack_44;
  int local_40 [2];
  undefined8 local_38;
  undefined8 local_30;
  
  pfVar7 = *(float **)(param_9 + 0x5c);
  local_40[0] = 0;
  psVar6 = *(short **)(param_9 + 0x26);
  iVar5 = 0;
  bVar1 = *(byte *)(pfVar7 + 0x45);
  if (bVar1 == 2) {
    pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
    fVar2 = FLOAT_803e5148;
    if (FLOAT_803e5148 <= pfVar7[0x44]) {
      *(undefined *)((int)pfVar7 + 0x116) = 0;
      *(undefined *)(pfVar7 + 0x45) = 3;
      pfVar7[0x44] = pfVar7[0x44] - fVar2;
      ObjGroup_AddObject((int)param_9,0x2f);
      DAT_803de7a0 = DAT_803de7a0 + -1;
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      if (*psVar6 == 0x72a) {
        dVar10 = (double)FLOAT_803e5104;
        fVar2 = FLOAT_803e5100;
        while ((iVar5 == 0 && (fVar2 < (float)(dVar10 * (double)FLOAT_803dc074)))) {
          iVar5 = FUN_80006a10((double)pfVar7[0x42],pfVar7);
          if ((iVar5 == 0) && (pfVar7[4] != 0.0)) {
            (**(code **)(*DAT_803dd71c + 0x90))(pfVar7);
          }
          fVar2 = (pfVar7[0x1a] - *(float *)(param_9 + 0x40)) *
                  (pfVar7[0x1a] - *(float *)(param_9 + 0x40)) +
                  (pfVar7[0x1c] - *(float *)(param_9 + 0x44)) *
                  (pfVar7[0x1c] - *(float *)(param_9 + 0x44));
        }
      }
      else {
        iVar5 = FUN_80006a10((double)pfVar7[0x42],pfVar7);
        if ((iVar5 == 0) && (pfVar7[4] != 0.0)) {
          (**(code **)(*DAT_803dd71c + 0x90))(pfVar7);
        }
      }
      *(undefined *)((int)pfVar7 + 0x116) = 10;
      FUN_80035b84((int)param_9,(ushort)*(byte *)(*(int *)(param_9 + 0x28) + 0x62));
      if (*psVar6 == 0x72a) {
        fVar2 = FLOAT_803e5110 + pfVar7[0x1b];
      }
      else {
        fVar2 = pfVar7[0x1b];
      }
      dVar10 = (double)fVar2;
      pfVar7[0x43] = FLOAT_803e5130 * FLOAT_803dc074 + pfVar7[0x43];
      *(float *)(param_9 + 8) = pfVar7[0x43] * FLOAT_803dc074 + *(float *)(param_9 + 8);
      if ((double)*(float *)(param_9 + 8) < dVar10) {
        if ((*psVar6 == 0x72a) && ((double)*(float *)(param_9 + 8) < (double)FLOAT_803e5134)) {
          iVar5 = 1;
        }
        if ((iVar5 == 0) && (FLOAT_803e5104 < pfVar7[0x43] * pfVar7[0x43])) {
          FUN_800067e8((uint)param_9,0x41e,6);
        }
        pfVar7[0x43] = pfVar7[0x43] * FLOAT_803e5138;
        *(float *)(param_9 + 8) =
             (float)((double)FLOAT_803e513c * dVar10 - (double)*(float *)(param_9 + 8));
      }
      *(float *)(param_9 + 6) = pfVar7[0x1a];
      *(float *)(param_9 + 10) = pfVar7[0x1c];
      iVar3 = FUN_80017730();
      *param_9 = (short)iVar3;
      if (*(char *)((int)pfVar7 + 0x115) == '\0') {
        local_30 = (double)CONCAT44(0x43300000,(int)(short)param_9[2] ^ 0x80000000);
        param_9[2] = (short)(int)-(FLOAT_803e5140 * FLOAT_803dc074 -
                                  (float)(local_30 - DOUBLE_803e5120));
        if ((short)param_9[2] < 0x3a00) {
          *(undefined *)((int)pfVar7 + 0x115) = 1;
        }
      }
      else {
        local_38 = (double)CONCAT44(0x43300000,(int)(short)param_9[2] ^ 0x80000000);
        param_9[2] = (short)(int)(FLOAT_803e5140 * FLOAT_803dc074 +
                                 (float)(local_38 - DOUBLE_803e5120));
        if (0x5000 < (short)param_9[2]) {
          *(undefined *)((int)pfVar7 + 0x115) = 0;
        }
      }
      dVar10 = DOUBLE_803e5120;
      dVar9 = (double)(FLOAT_803e5144 * FLOAT_803dc074);
      dVar8 = (double)pfVar7[0x42];
      local_30 = (double)CONCAT44(0x43300000,(int)(short)param_9[1] ^ 0x80000000);
      iVar3 = (int)(dVar9 * dVar8 + (double)(float)(local_30 - DOUBLE_803e5120));
      local_38 = (double)(longlong)iVar3;
      param_9[1] = (short)iVar3;
      iVar3 = ObjHits_GetPriorityHit((int)param_9,local_40,&iStack_44,&uStack_48);
      if ((((iVar5 != 0) || (iVar4 = FUN_80017a98(), local_40[0] == iVar4)) || (iVar3 - 0xeU < 2))
         || (iVar3 == 0x13)) {
        if (iVar5 == 0) {
          *(undefined *)((int)pfVar7 + 0x116) = 0;
        }
        else {
          *(undefined *)((int)pfVar7 + 0x116) = 5;
        }
        FUN_80017760(0,2);
        FUN_801a6378(dVar10,dVar8,dVar9,param_4,param_5,param_6,param_7,param_8,(uint)param_9);
      }
    }
    else {
      pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
      fVar2 = FLOAT_803e5148;
      if (FLOAT_803e5148 <= pfVar7[0x44]) {
        *(undefined *)(pfVar7 + 0x45) = 2;
        pfVar7[0x44] = pfVar7[0x44] - fVar2;
      }
    }
  }
  else if (bVar1 < 4) {
    pfVar7[0x44] = pfVar7[0x44] + FLOAT_803dc074;
    if ((double)FLOAT_803e514c <= (double)pfVar7[0x44]) {
      FUN_80017ac8((double)pfVar7[0x44],param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9);
      return;
    }
  }
  if (*(char *)((int)pfVar7 + 0x116) == '\0') {
    ObjHits_DisableObject((int)param_9);
    ObjHits_SetHitVolumeSlot((int)param_9,*(undefined *)((int)pfVar7 + 0x116),0,0);
  }
  else {
    ObjHits_EnableObject((int)param_9);
    ObjHits_SetHitVolumeSlot((int)param_9,*(undefined *)((int)pfVar7 + 0x116),1,0);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801A5858(void) {}
void fn_801A5D80(void) {}
void fn_801A5D84(void) {}
void fn_801A6050(void) {}
void fn_801A6628(void) {}
void fn_801A6774(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_801A57E8(void) { return 0x14; }
int fn_801A57F0(void) { return 0x0; }
int fn_801A5F70(void) { return 0x118; }
int fn_801A5F78(void) { return 0x0; }
int fn_801A66FC(void) { return 0x0; }
int fn_801A6704(void) { return 0x0; }
