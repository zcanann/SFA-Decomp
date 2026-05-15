#include "ghidra_import.h"
#include "main/dll/DF/DFcradle.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810ec();

extern undefined4 DAT_80326928;
extern undefined4 DAT_8032692a;
extern undefined4 DAT_8032692c;
extern undefined4 DAT_8032692e;
extern undefined4 DAT_80326930;
extern undefined4 DAT_80326932;
extern undefined4 DAT_803269a8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5a28;
extern f64 DOUBLE_803e5a60;
extern f32 lbl_803DC074;
extern f32 lbl_803E5A24;
extern f32 lbl_803E5A38;
extern f32 lbl_803E5A3C;
extern f32 lbl_803E5A40;
extern f32 lbl_803E5A44;
extern f32 lbl_803E5A48;
extern f32 lbl_803E5A4C;
extern f32 lbl_803E5A50;
extern f32 lbl_803E5A54;
extern f32 lbl_803E5A58;

/*
 * --INFO--
 *
 * Function: FUN_801c053c
 * EN v1.0 Address: 0x801C053C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C05BC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c053c(int param_1)
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
 * Function: FUN_801c0564
 * EN v1.0 Address: 0x801C0564
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x801C05F0
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0564(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  int *piVar2;
  undefined2 *puVar3;
  int iVar4;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar5 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_80017ae8();
  if (((uVar1 & 0xff) != 0) && (uVar1 = GameBit_Get(0x26b), uVar1 != 0)) {
    GameBit_Set(0x26b,0);
    piVar2 = ObjGroup_GetObjects(4,local_28);
    iVar4 = 0;
    if (0 < local_28[0]) {
      do {
        in_r8 = *piVar2;
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326928) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692a) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692c) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_8032692e) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326930) {
          iVar4 = iVar4 + 1;
        }
        if ((int)*(short *)(in_r8 + 0x46) == (uint)DAT_80326932) {
          iVar4 = iVar4 + 1;
        }
        piVar2 = piVar2 + 1;
        local_28[0] = local_28[0] + -1;
      } while (local_28[0] != 0);
    }
    if (iVar4 < 10) {
      uVar1 = randomGetRange(0,5);
      puVar3 = FUN_80017aa4(0x30,(&DAT_80326928)[uVar1]);
      if (puVar3 != (undefined2 *)0x0) {
        *(undefined *)(puVar3 + 0xd) = 0x14;
        puVar3[0x16] = 0xffff;
        puVar3[0xe] = 0xffff;
        uStack_1c = randomGetRange(0xfffffea2,0x15e);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        *(float *)(puVar3 + 4) =
             *(float *)(param_9 + 0xc) +
             (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 6) = lbl_803E5A24 + *(float *)(param_9 + 0x10);
        uStack_14 = randomGetRange(0xfffffea2,0x15e);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        dVar6 = (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5a28);
        *(float *)(puVar3 + 8) = (float)((double)*(float *)(param_9 + 0x14) + dVar6);
        puVar3[0x12] = 0xffff;
        *(undefined *)(puVar3 + 2) = *(undefined *)(iVar5 + 4);
        *(undefined *)(puVar3 + 3) = *(undefined *)(iVar5 + 6);
        *(undefined *)((int)puVar3 + 5) = *(undefined *)(iVar5 + 5);
        *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar5 + 7);
        puVar3[0x17] = 3;
        iVar5 = FUN_80017ae4(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                             in_r8,in_r9,in_r10);
        if (iVar5 != 0) {
          iVar4 = 3;
          do {
            FUN_800810ec(iVar5,2,2,100,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0828
 * EN v1.0 Address: 0x801C0828
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x801C086C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c0828(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = GameBit_Get((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801c08d4
 * EN v1.0 Address: 0x801C08D4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801C0928
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c08d4(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0908
 * EN v1.0 Address: 0x801C0908
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x801C0968
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0908(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = GameBit_Get((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_1,*(short *)(iVar2 + 0x1a) + 0x4c6,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c8,0,2,0xffffffff,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c09b0
 * EN v1.0 Address: 0x801C09B0
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801C0A7C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c09b0(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x10);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x10) = 0;
  }
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0a18
 * EN v1.0 Address: 0x801C0A18
 * EN v1.0 Size: 1164b
 * EN v1.1 Address: 0x801C0AF0
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0a18(uint param_1)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  double dVar6;
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if ((int)*(short *)(iVar4 + 0x20) == 0xffffffff) {
    *(float *)(pbVar5 + 0xc) = *(float *)(pbVar5 + 0xc) - lbl_803DC074;
    if (*(float *)(pbVar5 + 0xc) <= lbl_803E5A38) {
      uVar1 = randomGetRange(0xf0,0x1e0);
      *(float *)(pbVar5 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  else {
    uVar1 = GameBit_Get((int)*(short *)(iVar4 + 0x20));
    if (uVar1 != 0) {
      GameBit_Set((int)*(short *)(iVar4 + 0x20),0);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_803269a8 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  if (lbl_803E5A38 < *(float *)(pbVar5 + 4)) {
    if ((*pbVar5 & 1) != 0) {
      *pbVar5 = *pbVar5 & 0xfe;
      ObjHits_SetHitVolumeSlot(param_1,9,1,0);
      ObjHitbox_SetSphereRadius(param_1,0xf);
      ObjHits_EnableObject(param_1);
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        iVar3 = 0;
        do {
          if (*(short *)(iVar4 + 0x1a) == 0) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cc,0,2,0xffffffff,0);
          }
          else {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x4c9,0,2,0xffffffff,0);
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 < 0x32);
      }
      iVar3 = FUN_80017a98();
      if ((iVar3 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
        dVar6 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 <= (double)lbl_803E5A3C) {
          dVar6 = (double)(lbl_803E5A40 - (float)(dVar6 / (double)lbl_803E5A3C));
          FUN_8000691c((double)(float)((double)lbl_803E5A44 * dVar6),(double)lbl_803E5A44,
                       (double)lbl_803E5A48);
          FUN_80006b94((double)(float)((double)lbl_803E5A4C * dVar6));
        }
      }
      if (*(int *)(pbVar5 + 0x10) == 0) {
        piVar2 = FUN_80017624(param_1,'\x01');
        *(int **)(pbVar5 + 0x10) = piVar2;
        if (*(int *)(pbVar5 + 0x10) != 0) {
          FUN_800175b0(*(int *)(pbVar5 + 0x10),2);
          FUN_800175a0(*(int *)(pbVar5 + 0x10),1);
          if (*(short *)(iVar4 + 0x1a) == 0) {
            FUN_8001759c(*(int *)(pbVar5 + 0x10),0x7f,0xff,0,0);
          }
          else {
            FUN_8001759c(*(int *)(pbVar5 + 0x10),0xff,0x7f,0,0);
          }
          FUN_800175d0((double)lbl_803E5A50,(double)lbl_803E5A54,*(int *)(pbVar5 + 0x10));
          FUN_800175cc((double)lbl_803E5A38,*(int *)(pbVar5 + 0x10),'\x01');
          FUN_800175cc((double)(*(float *)(pbVar5 + 4) / lbl_803E5A58),*(int *)(pbVar5 + 0x10),
                       '\0');
        }
      }
      FUN_80006824(param_1,0x188);
    }
    *(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - lbl_803DC074;
    if (lbl_803E5A38 < *(float *)(pbVar5 + 4)) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x4ca,0,2,0xffffffff,0);
      if (*(short *)(iVar4 + 0x1a) == 0) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cd,0,2,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x4cb,0,2,0xffffffff,0);
      }
    }
    else {
      *(float *)(pbVar5 + 4) = lbl_803E5A38;
      if (*(uint *)(pbVar5 + 0x10) != 0) {
        FUN_80017620(*(uint *)(pbVar5 + 0x10));
        pbVar5[0x10] = 0;
        pbVar5[0x11] = 0;
        pbVar5[0x12] = 0;
        pbVar5[0x13] = 0;
      }
      ObjHits_SetHitVolumeSlot(param_1,0,0,0);
      ObjHitbox_SetSphereRadius(param_1,0);
      ObjHits_DisableObject(param_1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbossfire_release
 * EN v1.0 Address: 0x801C0A58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B30
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbossfire_initialise
 * EN v1.0 Address: 0x801C0A5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B34
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: ccriverflow_getExtraSize
 * EN v1.0 Address: 0x801C0A60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C0B38
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ccriverflow_getExtraSize(void)
{
  return 1;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_render
 * EN v1.0 Address: 0x801C0A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B88
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_render(void)
{
}
