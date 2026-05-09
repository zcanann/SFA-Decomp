#include "ghidra_import.h"
#include "main/dll/MMP/mmp_levelcontrol.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern int FUN_80017a90();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern uint FUN_80060058();
extern undefined4 FUN_800600b4();
extern undefined4 FUN_800600c4();
extern int FUN_800600d4();
extern undefined4 FUN_80193a50();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286838();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();

extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e4c88;
extern f32 lbl_803E4C68;
extern f32 lbl_803E4C6C;
extern f32 lbl_803E4C70;
extern f32 lbl_803E4C74;
extern f32 lbl_803E4C78;
extern f32 lbl_803E4C7C;
extern f32 lbl_803E4C80;
extern f32 lbl_803E4C94;
extern f32 lbl_803E4C98;

/*
 * --INFO--
 *
 * Function: FUN_8019443c
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8019443c(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  *pbVar3 = *(byte *)(param_2 + 0x1c) & 1;
  pbVar3[1] = 0;
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x18));
  if ((uVar1 != 0) && (*pbVar3 = *pbVar3 ^ 1, *(char *)(param_2 + 0x1a) == '\x01')) {
    pbVar3[1] = pbVar3[1] | 1;
  }
  iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar2 = FUN_8005af70(iVar2);
  if (((iVar2 != 0) && ((*(byte *)(param_2 + 0x1c) & 4) != 0)) &&
     (*(char *)(param_2 + 0x1b) != '\0')) {
    FUN_80193a50(iVar2,param_1,(char *)pbVar3,param_2);
  }
  pbVar3[1] = pbVar3[1] | 2;
  if ((*(byte *)(param_2 + 0x1c) & 4) != 0) {
    pbVar3[1] = pbVar3[1] | 4;
  }
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x18));
  pbVar3[2] = (byte)uVar1;
  pbVar3[3] = (byte)uVar1;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80194544(int param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar1 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  iVar1 = FUN_8005af70(iVar1);
  if (iVar1 == 0) {
    *pbVar4 = *pbVar4 | 1;
  }
  else {
    uVar2 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
    pbVar4[2] = pbVar4[4] & (byte)uVar2;
    if (pbVar4[3] != pbVar4[2]) {
      pbVar4[1] = pbVar4[1] ^ 1;
      *pbVar4 = *pbVar4 | 1;
    }
    pbVar4[3] = pbVar4[2];
    if ((*pbVar4 & 1) != 0) {
      *pbVar4 = *pbVar4 & 0xfe;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801945fc
 * EN v1.0 Address: 0x801945FC
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801948A4
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801945fc(int param_1,int param_2)
{
  byte bVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  pbVar4 = *(byte **)(param_1 + 0xb8);
  pbVar4[1] = *(byte *)(param_2 + 0x1b);
  pbVar4[4] = (byte)(1 << (uint)*(byte *)(param_2 + 0x1c));
  uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x18));
  if ((pbVar4[4] & uVar2) != 0) {
    pbVar4[1] = pbVar4[1] ^ 1;
  }
  iVar3 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10));
  FUN_8005af70(iVar3);
  uVar2 = FUN_80017690((int)*(short *)(param_2 + 0x18));
  bVar1 = pbVar4[4] & (byte)uVar2;
  pbVar4[2] = bVar1;
  pbVar4[3] = bVar1;
  *pbVar4 = *pbVar4 | 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801946b8
 * EN v1.0 Address: 0x801946B8
 * EN v1.0 Size: 444b
 * EN v1.1 Address: 0x801949B8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801946b8(void)
{
  float fVar1;
  float fVar2;
  ushort *puVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  double in_f27;
  double dVar9;
  double in_f28;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  float local_a8;
  float local_a4;
  float local_a0;
  ushort local_9c [6];
  float local_90;
  float local_8c;
  float local_88;
  undefined4 local_80;
  uint uStack_7c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar14 = FUN_80286838();
  puVar3 = (ushort *)((ulonglong)uVar14 >> 0x20);
  iVar5 = (int)uVar14;
  iVar8 = *(int *)(puVar3 + 0x26);
  iVar7 = 6;
  dVar9 = (double)lbl_803E4C68;
  dVar10 = (double)lbl_803E4C6C;
  dVar11 = (double)lbl_803E4C70;
  dVar12 = (double)lbl_803E4C74;
  dVar13 = DOUBLE_803e4c88;
  do {
    uStack_7c = FUN_80017760(0xffffff9c,100);
    uStack_7c = uStack_7c ^ 0x80000000;
    local_80 = 0x43300000;
    local_a8 = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - dVar13));
    local_a4 = (float)dVar10;
    local_a0 = (float)dVar10;
    uVar4 = FUN_80017760(0xffff8001,0x8000);
    local_9c[2] = (ushort)uVar4;
    local_9c[1] = 0;
    local_9c[0] = 0;
    FUN_80017748(local_9c,&local_a8);
    local_a0 = (float)((double)local_a0 - dVar11);
    FUN_80017748(puVar3,&local_a8);
    local_9c[2] = *(undefined2 *)(iVar8 + 0x1c);
    local_9c[0] = *puVar3;
    local_90 = *(float *)(puVar3 + 0xc) + local_a8;
    local_8c = (float)(dVar12 + (double)(*(float *)(puVar3 + 0xe) + local_a4));
    local_88 = *(float *)(puVar3 + 0x10) + local_a0;
    (**(code **)(*DAT_803dd708 + 8))(puVar3,0xca,local_9c,0x200001,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(puVar3,0xcb,local_9c,0x200001,0xffffffff,0);
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  puVar6 = *(uint **)(puVar3 + 0x5c);
  fVar1 = *(float *)(iVar5 + 0x10) - *(float *)(puVar3 + 8);
  if (((lbl_803E4C78 <= fVar1) && (fVar1 <= lbl_803E4C7C)) &&
     (fVar1 = *(float *)(iVar5 + 0xc) - *(float *)(puVar3 + 6),
     fVar2 = *(float *)(iVar5 + 0x14) - *(float *)(puVar3 + 10),
     fVar1 * fVar1 + fVar2 * fVar2 <= lbl_803E4C80)) {
    *puVar6 = *puVar6 + 0x3c;
    uStack_7c = *puVar6 ^ 0x80000000;
    local_80 = 0x43300000;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80194874
 * EN v1.0 Address: 0x80194874
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80194C20
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80194874(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x23);
  ObjGroup_RemoveObject(param_1,0x31);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801948b0
 * EN v1.0 Address: 0x801948B0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80194C5C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801948b0(int param_1)
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
 * Function: FUN_801948d8
 * EN v1.0 Address: 0x801948D8
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x80194C8C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801948d8(uint param_1)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  float local_18 [4];
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (-1 < (char)*(byte *)(piVar2 + 1)) {
    if (*piVar2 < 3000) {
      iVar3 = FUN_80017a90();
      if (iVar3 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        local_18[0] = lbl_803E4C94;
        iVar1 = ObjGroup_FindNearestObject(5,param_1,local_18);
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,1);
          }
          FUN_800400b0();
        }
      }
    }
    else {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0x7f | 0x80;
      FUN_80017698((int)*(short *)(iVar3 + 0x18),1);
      FUN_80006824(param_1,0x109);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801949ec
 * EN v1.0 Address: 0x801949EC
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x80194DB8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801949ec(undefined2 *param_1,int param_2)
{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = *(undefined2 *)(param_2 + 0x24);
  ObjGroup_AddObject((int)param_1,0x23);
  ObjGroup_AddObject((int)param_1,0x31);
  uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x18));
  if (uVar1 != 0) {
    *(byte *)(puVar2 + 1) = *(byte *)(puVar2 + 1) & 0x7f | 0x80;
    *puVar2 = 3000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80194a70(int param_1,byte param_2)
{
  int iVar1;
  
  if ((param_1 == 0) || (iVar1 = *(int *)(param_1 + 0xb8), iVar1 == 0)) {
    return (double)lbl_803E4C98;
  }
  if (param_2 == 4) {
    return (double)*(float *)(iVar1 + 0x44);
  }
  if (param_2 < 4) {
    if (param_2 == 2) {
      return (double)*(float *)(iVar1 + 0x40);
    }
    if (1 < param_2) {
      return (double)(*(float *)(param_1 + 0x10) + *(float *)(iVar1 + 0x44));
    }
    if (param_2 != 0) {
      return (double)(*(float *)(param_1 + 0xc) + *(float *)(iVar1 + 0x40));
    }
  }
  else {
    if (param_2 == 6) {
      return (double)*(float *)(iVar1 + 0x48);
    }
    if (param_2 < 6) {
      return (double)(*(float *)(param_1 + 0x14) + *(float *)(iVar1 + 0x48));
    }
  }
  return (double)lbl_803E4C98;
}

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80194b10(undefined4 param_1,undefined4 param_2,int param_3)
{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  iVar4 = (int)uVar10;
  iVar8 = 0;
  iVar7 = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(ushort *)(param_3 + 0x9a); iVar6 = iVar6 + 1) {
    puVar2 = (ushort *)FUN_800600c4(param_3,iVar6);
    uVar3 = FUN_80060058((int)puVar2);
    if ((int)*(char *)((int)((ulonglong)uVar10 >> 0x20) + 0x28) == uVar3) {
      *(ushort *)(*(int *)(iVar4 + 0x10) + iVar8) = puVar2[3];
      *(ushort *)(*(int *)(iVar4 + 0x14) + iVar8) = puVar2[4];
      iVar8 = iVar8 + 2;
      uVar1 = puVar2[10];
      iVar9 = iVar7;
      for (uVar3 = (uint)*puVar2; (int)uVar3 < (int)(uint)uVar1; uVar3 = uVar3 + 1) {
        puVar2 = (ushort *)FUN_800600b4(param_3,uVar3);
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)*puVar2 * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 2) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 4) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[1] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 6) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 8) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 10) = puVar5[2];
        puVar5 = (undefined2 *)(*(int *)(param_3 + 0x58) + (uint)puVar2[2] * 6);
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0xc) = *puVar5;
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0xe) = puVar5[1];
        *(undefined2 *)(*(int *)(iVar4 + 0xc) + iVar9 + 0x10) = puVar5[2];
        iVar9 = iVar9 + 0x12;
        iVar7 = iVar7 + 0x12;
      }
    }
  }
  iVar6 = 0;
  for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(param_3 + 0xa1); iVar7 = iVar7 + 1) {
    iVar8 = FUN_800600d4(param_3,iVar7);
    *(undefined2 *)(*(int *)(iVar4 + 0x28) + iVar6) = *(undefined2 *)(iVar8 + 6);
    *(undefined2 *)(*(int *)(iVar4 + 0x2c) + iVar6) = *(undefined2 *)(iVar8 + 0xc);
    *(undefined2 *)(*(int *)(iVar4 + 0x30) + iVar6) = *(undefined2 *)(iVar8 + 8);
    *(undefined2 *)(*(int *)(iVar4 + 0x34) + iVar6) = *(undefined2 *)(iVar8 + 0xe);
    *(undefined2 *)(*(int *)(iVar4 + 0x38) + iVar6) = *(undefined2 *)(iVar8 + 10);
    *(undefined2 *)(*(int *)(iVar4 + 0x3c) + iVar6) = *(undefined2 *)(iVar8 + 0x10);
    iVar6 = iVar6 + 2;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wallanimator_getExtraSize(void)
{
  return 8;
}

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int xyzanimator_getExtraSize(void)
{
  return 0x50;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3FF8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4004;
#pragma peephole off
void wallanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3FF8); }
void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4004); }
#pragma peephole reset
