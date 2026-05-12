#include "ghidra_import.h"
#include "main/dll/SH/SHkillermushroom.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80017620();
extern undefined4 GameBit_Set(int eventId, int value);
extern double FUN_80017714();
extern uint FUN_80017760();
extern undefined4 FUN_80017a28();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RefreshObjectState();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_8013651c();
extern undefined4 FUN_801d2db8();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_80327960;
extern undefined4 DAT_80327964;
extern undefined4 DAT_80327968;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5ff8;
extern f64 DOUBLE_803e6038;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e5ff0;
extern f32 FLOAT_803e5ff4;
extern f32 FLOAT_803e6000;
extern f32 FLOAT_803e6004;
extern f32 FLOAT_803e6010;
extern f32 FLOAT_803e6014;
extern f32 FLOAT_803e6028;
extern f32 FLOAT_803e602c;

/*
 * --INFO--
 *
 * Function: SHkillermushroom_free
 * EN v1.0 Address: 0x801D2C54
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801D3138
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHkillermushroom_free(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: bombplantspore_getExtraSize
 * EN v1.0 Address: 0x801D3378
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int bombplantspore_getExtraSize(void)
{
  return 0x2b4;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2c74
 * EN v1.0 Address: 0x801D2C74
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801D3160
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2c74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,int param_11)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x26);
  iVar1 = FUN_80017a90();
  if (iVar1 != 0) {
    FUN_8013651c(iVar1);
  }
  FUN_80006824((uint)param_9,0xa3);
  *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 0x40
  ;
  FUN_8008112c((double)FLOAT_803e6010,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0,1,1,1,0,1,0);
  *(undefined *)(param_11 + 0x14) = 1;
  *(byte *)(param_11 + 0x15) = *(byte *)(param_11 + 0x15) | 2;
  if ((int)*(short *)(iVar2 + 0x1c) == 0xffffffff) {
    iVar1 = 0;
    do {
      FUN_801d2db8(param_9);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 3);
  }
  else {
    GameBit_Set((int)*(short *)(iVar2 + 0x1c),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2dd0
 * EN v1.0 Address: 0x801D2DD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D3244
 * EN v1.1 Size: 1508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2dd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,uint *param_12,
                 float *param_13,undefined4 *param_14,float *param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d2dd4
 * EN v1.0 Address: 0x801D2DD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D3828
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2dd4(undefined2 *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d2dd8
 * EN v1.0 Address: 0x801D2DD8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801D3970
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2dd8(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  uVar1 = *(uint *)(iVar2 + 0x270);
  if (uVar1 != 0) {
    FUN_80017620(uVar1);
    *(undefined4 *)(iVar2 + 0x270) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2e30
 * EN v1.0 Address: 0x801D2E30
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801D39C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2e30(int param_1,int param_2)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar1 = *(ushort *)(iVar4 + 0x1c);
  uVar2 = FUN_80017760(0x1e,0x2d);
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038);
  uVar2 = FUN_80017760(0x78,0xb4);
  *(float *)(param_2 + 0x284) =
       *(float *)(param_2 + 0x298) +
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038);
  uVar2 = FUN_80017760(0xfffff830,2000);
  *(short *)(param_2 + 0x2aa) = *(short *)(param_2 + 0x2a8) + (short)uVar2;
  iVar3 = (int)*(short *)(param_2 + 0x2aa) - (uint)uVar1;
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  if (*(short *)(iVar4 + 0x1a) < iVar3) {
    *(ushort *)(param_2 + 0x2aa) = uVar1 + *(short *)(iVar4 + 0x1a);
  }
  if (iVar3 < -(int)*(short *)(iVar4 + 0x1a)) {
    *(ushort *)(param_2 + 0x2aa) = uVar1 - *(short *)(iVar4 + 0x1a);
  }
  uVar2 = FUN_80017760(900,0x514);
  *(float *)(param_2 + 0x29c) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038) / FLOAT_803e6028;
  *(float *)(param_2 + 0x27c) = FLOAT_803e602c;
  dVar5 = (double)FUN_80293f90();
  *(float *)(param_2 + 0x290) = (float)dVar5;
  dVar5 = (double)FUN_80294964();
  *(float *)(param_2 + 0x294) = (float)dVar5;
  return;
}
