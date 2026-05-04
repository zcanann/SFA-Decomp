#include "ghidra_import.h"
#include "main/dll/DF/dll_198.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006930();
extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8004812c();
extern void fn_8005D108();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_80070ec8();
extern undefined4 FUN_800712d4();
extern undefined4 FUN_80071d70();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern undefined4 FUN_80080f8c();
extern undefined4 FUN_801c0fd8();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();

extern undefined4 DAT_80326a40;
extern undefined4 DAT_80326aa0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcbb0;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5AB0;

/*
 * --INFO--
 *
 * Function: FUN_801c2278
 * EN v1.0 Address: 0x801C2278
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x801C2460
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c2278(int param_1)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int local_18 [3];
  
  piVar3 = *(int **)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,0x17);
  uVar1 = piVar3[0xb];
  if ((uVar1 != 0) && (uVar1 != 0)) {
    FUN_80017814(uVar1);
  }
  iVar4 = *piVar3;
  if (iVar4 != 0) {
    piVar3 = ObjGroup_GetObjects(0x17,local_18);
    for (iVar2 = 0; iVar2 < local_18[0]; iVar2 = iVar2 + 1) {
      if (*piVar3 == iVar4) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x44))(iVar4);
      }
      piVar3 = piVar3 + 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c232c
 * EN v1.0 Address: 0x801C232C
 * EN v1.0 Size: 776b
 * EN v1.1 Address: 0x801C2510
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c232c(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
  byte bVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  undefined uVar6;
  short sVar5;
  float *pfVar7;
  int iVar8;
  int *piVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined8 uVar11;
  undefined4 local_98;
  byte local_94;
  byte local_93;
  undefined local_92 [2];
  short asStack_90 [68];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286838();
  puVar3 = (ushort *)((ulonglong)uVar11 >> 0x20);
  local_98 = (undefined4)uVar11;
  piVar9 = *(int **)(puVar3 + 0x5c);
  iVar8 = *(int *)(puVar3 + 0x26);
  if (((int)*(short *)(iVar8 + 0x1c) == 0) ||
     (uVar4 = FUN_80017690((int)*(short *)(iVar8 + 0x1c)), uVar4 == 0)) {
    if (*(char *)(puVar3 + 0x1b) == '\0') {
      FUN_80006824((uint)puVar3,0x475);
    }
    if (*(byte *)(puVar3 + 0x1b) < 0x46) {
      *(byte *)(puVar3 + 0x1b) = *(byte *)(puVar3 + 0x1b) + DAT_803dc070;
    }
    else {
      *(undefined *)(puVar3 + 0x1b) = 0x46;
    }
  }
  else {
    bVar1 = *(byte *)(puVar3 + 0x1b);
    if (bVar1 == 0x46) {
      FUN_80006824((uint)puVar3,0x476);
    }
    iVar2 = (uint)bVar1 - (uint)DAT_803dc070;
    if (iVar2 < 1) {
      *(undefined *)(puVar3 + 0x1b) = 0;
      goto LAB_801c2808;
    }
    *(char *)(puVar3 + 0x1b) = (char)iVar2;
  }
  if ((((*(byte *)(iVar8 + 0x18) & 1) != 0) && (*piVar9 != 0)) && (piVar9[0xb] != 0)) {
    dVar10 = (double)*(float *)(puVar3 + 4);
    *(float *)(puVar3 + 4) = lbl_803E5A90;
    FUN_80006930((double)lbl_803E5AB0,0,param_3,puVar3,(float *)0x0);
    *(float *)(puVar3 + 4) = (float)dVar10;
    FUN_80071f90();
    FUN_80071d70();
    FUN_80071f8c();
    if (*(char *)(iVar8 + 0x1b) == '\x01') {
      local_94 = 0xff;
      local_93 = 0xff;
      local_92[0] = 0xff;
    }
    else {
      *(undefined *)(puVar3 + 0x1b) = 0xff;
      FUN_80080f8c(0,local_92,&local_93,&local_94);
      local_93 = (byte)((uint)local_93 * 200 >> 8);
      local_94 = (byte)((uint)local_94 * 0xaa >> 8);
    }
    if (*(byte *)(puVar3 + 0x1b) < 0x47) {
      FUN_800712d4();
      uVar6 = (undefined)((int)((uint)*(byte *)(puVar3 + 0x1b) * 2) >> 1);
    }
    else {
      FUN_80070ec8();
      uVar6 = 0xff;
    }
    FUN_8004812c(*(int *)(&DAT_803dcbb0 + (uint)*(byte *)(iVar8 + 0x1b) * 4),0);
    FUN_8005d370(&local_98,local_92[0],local_93,local_94,uVar6);
    pfVar7 = *(float **)piVar9[0xb];
    for (sVar5 = 0; (int)sVar5 < (int)(*(byte *)(piVar9[0xb] + 8) - 1); sVar5 = sVar5 + 1) {
      FUN_801c0fd8(&DAT_80326a40,(int)*(short *)(piVar9 + 6),pfVar7,pfVar7 + 0xd,asStack_90);
      fn_8005D108((int)asStack_90,-0x7fd3d528,6);
      pfVar7 = pfVar7 + 0xd;
    }
    if (*(char *)(iVar8 + 0x1b) == '\x01') {
      FUN_800068c4((uint)puVar3,0x480);
      FUN_800712d4();
      uVar4 = FUN_80017760(0,(uint)*(byte *)(puVar3 + 0x1b));
      FUN_8005d370(&local_98,local_92[0],local_93,local_94,*(char *)(puVar3 + 0x1b) + (char)uVar4);
      pfVar7 = *(float **)piVar9[0xb];
      for (sVar5 = 0; (int)sVar5 < (int)(*(byte *)(piVar9[0xb] + 8) - 1); sVar5 = sVar5 + 1) {
        FUN_801c0fd8(&DAT_80326aa0,(int)*(short *)(piVar9 + 6),pfVar7,pfVar7 + 0xd,asStack_90);
        fn_8005D108((int)asStack_90,-0x7fd3d528,6);
        pfVar7 = pfVar7 + 0xd;
      }
    }
  }
LAB_801c2808:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_getExtraSize
 * EN v1.0 Address: 0x801C281C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C29EC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_door2speci_getExtraSize(void)
{
  return 6;
}
