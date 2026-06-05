#include "ghidra_import.h"
#include "main/dll/pressureSwitch.h"
#include "main/mapEvent.h"
#include "main/audio/sfx_ids.h"

#define SFXstaff_proj_outofmagic 0x236
#define SFXfox_treadwater122 0x237
#define SFXfox_treadwater222 0x238
#define SFXfox_treadwater422 0x23a
#define SFXand_swipe2 0x32b

extern undefined4 FUN_800033a8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc8d8;
extern undefined4 DAT_803dc8e0;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de6d0;
extern undefined4 DAT_803de6d8;
extern undefined4 DAT_803de6e0;
extern f64 DOUBLE_803e32d8;
extern f64 DOUBLE_803e32e0;
extern f64 DOUBLE_803e3340;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E32A0;
extern f32 lbl_803E32A4;
extern f32 lbl_803E32A8;
extern f32 lbl_803E32AC;
extern f32 lbl_803E32B0;
extern f32 lbl_803E32BC;
extern f32 lbl_803E32C0;
extern f32 lbl_803E32C4;
extern f32 lbl_803E32C8;
extern f32 lbl_803E32CC;
extern f32 lbl_803E32D0;
extern f32 lbl_803E32D4;
extern f32 lbl_803E32E8;
extern f32 lbl_803E32EC;
extern f32 lbl_803E32F0;
extern f32 lbl_803E32F4;
extern f32 lbl_803E32FC;
extern f32 lbl_803E3300;
extern f32 lbl_803E3304;
extern f32 lbl_803E3308;
extern f32 lbl_803E330C;
extern f32 lbl_803E3310;
extern f32 lbl_803E3314;
extern f32 lbl_803E3318;
extern f32 lbl_803E331C;
extern f32 lbl_803E3320;
extern f32 lbl_803E3324;
extern f32 lbl_803E3328;
extern f32 lbl_803E332C;
extern f32 lbl_803E3330;
extern f32 lbl_803E3334;
extern f32 lbl_803E3348;
extern f32 lbl_803E334C;
extern f32 lbl_803E3350;
extern f32 lbl_803E3354;
extern f32 lbl_803E3358;
extern f32 lbl_803E335C;
extern f32 lbl_803E3360;
extern f32 lbl_803E3364;

/*
 * --INFO--
 *
 * Function: FUN_8014e1dc
 * EN v1.0 Address: 0x8014E1DC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014E604
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureSwitch_freeSharedResource(void)
{
  if (DAT_803de6d0 != 0) {
    FUN_80006b0c(DAT_803de6d0);
    DAT_803de6d0 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e210
 * EN v1.0 Address: 0x8014E210
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014E638
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pressureSwitch_ensureSharedResource(void)
{
  if (DAT_803de6d0 == 0) {
    DAT_803de6d0 = FUN_80006b14(0x5a);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e244
 * EN v1.0 Address: 0x8014E244
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014E670
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e244()
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014e248
 * EN v1.0 Address: 0x8014E248
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8014EBD8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e248(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  FUN_80006810(param_1,SFXstaff_proj_outofmagic);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
    *puVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e2a8
 * EN v1.0 Address: 0x8014E2A8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8014EC38
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e2a8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((visible != 0) && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b818(param_1);
    if ((*(byte *)(iVar1 + 0x26) & 0x10) != 0) {
      FUN_8008111c((double)lbl_803E32E8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / lbl_803E32EC),param_1,3,(int *)0x0);
    }
    if ((*(byte *)(iVar1 + 0x26) & 8) != 0) {
      FUN_8008111c((double)lbl_803E32E8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / lbl_803E32EC),param_1,4,(int *)0x0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e374
 * EN v1.0 Address: 0x8014E374
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014ED20
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e374(uint param_1)
{
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    FUN_80006824(param_1,SFXand_swipe2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e3a8
 * EN v1.0 Address: 0x8014E3A8
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x8014ED54
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e3a8(ushort *param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  double dVar6;
  uint uStack_58;
  int iStack_54;
  undefined4 uStack_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack_40 [12];
  float local_34;
  undefined4 uStack_30;
  float local_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  piVar5 = *(int **)(param_1 + 0x5c);
  iVar4 = *piVar5;
  iVar3 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    iVar2 = FUN_80017a98();
    dVar6 = (double)FUN_8001771c((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
    if ((double)lbl_803E32F0 <= dVar6) {
      if ((double)lbl_803E32F4 < dVar6) {
        FUN_80006810((int)param_1,SFXstaff_proj_outofmagic);
      }
    }
    else {
      FUN_80006824((uint)param_1,SFXstaff_proj_outofmagic);
    }
    if ((*(byte *)(param_1 + 0x1b) == 0) || ((*(byte *)((int)piVar5 + 0x26) & 0x18) == 0)) {
      iVar2 = ObjHits_GetPriorityHitWithPosition((int)param_1,&uStack_50,&iStack_54,&uStack_58,&local_34,&uStack_30,
                           &local_2c);
      if (iVar2 != 0) {
        FUN_8000680c((int)param_1,0x7f);
        *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 0x10;
        FUN_80006824((uint)param_1,SFXdoor_unlocked);
        FUN_80006824((uint)param_1,SFXdoor_creak);
        FUN_80006824((uint)param_1,SFXfox_treadwater222);
        FUN_80006824((uint)param_1,SFXfoot_metal_run_2);
        local_34 = local_34 + lbl_803DDA58;
        local_2c = local_2c + lbl_803DDA5C;
        FUN_80081120(param_1,auStack_40,3,(int *)0x0);
        local_20 = (double)CONCAT44(0x43300000,*(short *)(iVar3 + 0x1c) * 0x3c ^ 0x80000000);
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(float)(local_20 - DOUBLE_803e32e0),*(undefined4 *)(iVar3 + 0x14));
        if ((int)*(short *)(iVar3 + 0x20) != 0xffffffff) {
          GameBit_Set((int)*(short *)(iVar3 + 0x20),1);
        }
      }
      ObjHits_SetHitVolumeSlot((int)param_1,10,1,0);
      ObjHits_EnableObject((int)param_1);
    }
    else {
      if ((*(byte *)((int)piVar5 + 0x26) & 0x10) != 0) {
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_28 - DOUBLE_803e32d8) - lbl_803DC074);
        local_20 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (*(byte *)(param_1 + 0x1b) < 7) {
          param_1[0x7a] = 0;
          param_1[0x7b] = 1;
          *(undefined *)(param_1 + 0x1b) = 0;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xef;
          FUN_80006810((int)param_1,SFXstaff_proj_outofmagic);
        }
        ObjHits_DisableObject((int)param_1);
      }
      if ((*(byte *)((int)piVar5 + 0x26) & 8) != 0) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_20 - DOUBLE_803e32d8) + lbl_803DC074);
        local_28 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (0xf8 < *(byte *)(param_1 + 0x1b)) {
          *(undefined *)(param_1 + 0x1b) = 0xff;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xf7;
        }
      }
    }
    iVar2 = FUN_80017a98();
    piVar5[1] = iVar2;
    iVar2 = piVar5[1];
    if (iVar2 != 0) {
      local_4c = *(float *)(iVar2 + 0x18) - *(float *)(param_1 + 0xc);
      local_48 = *(float *)(iVar2 + 0x1c) - *(float *)(param_1 + 0xe);
      local_44 = *(float *)(iVar2 + 0x20) - *(float *)(param_1 + 0x10);
      dVar6 = FUN_80293900((double)(local_44 * local_44 + local_4c * local_4c + local_48 * local_48)
                          );
      piVar5[4] = (int)(float)dVar6;
    }
    if (iVar4 != 0) {
      local_4c = *(float *)(iVar4 + 0x68) - *(float *)(param_1 + 0xc);
      local_48 = *(float *)(iVar4 + 0x6c) - *(float *)(param_1 + 0xe);
      local_44 = *(float *)(iVar4 + 0x70) - *(float *)(param_1 + 0x10);
      dVar6 = FUN_80293900((double)(local_44 * local_44 + local_4c * local_4c + local_48 * local_48)
                          );
      piVar5[5] = (int)(float)dVar6;
    }
    if (((*(byte *)((int)piVar5 + 0x26) & 2) != 0) && (lbl_803E32FC < (float)piVar5[5])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfd;
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 4;
    }
    if (((*(byte *)((int)piVar5 + 0x26) & 4) != 0) && ((float)piVar5[5] < lbl_803E3300)) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfb;
    }
    if (((((*(byte *)((int)piVar5 + 0x26) & 6) == 0) && (*(short *)(iVar3 + 0x1e) == 0)) &&
        (piVar5[1] != 0)) && ((float)piVar5[4] < (float)piVar5[6])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 2;
    }
    FUN_8014e244(param_1,piVar5);
  }
  else if ((((int)*(short *)(iVar3 + 0x20) == 0xffffffff) ||
           (uVar1 = GameBit_Get((int)*(short *)(iVar3 + 0x20)), uVar1 == 0)) &&
          (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0))
  {
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
    *(undefined *)(param_1 + 0x1b) = 1;
    *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 8;
    FUN_80006824((uint)param_1,SFXfox_treadwater122);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e898
 * EN v1.0 Address: 0x8014E898
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8014F1E4
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e898(int param_1,int param_2,int param_3)
{
  double dVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  int *piVar5;
  
  dVar1 = DOUBLE_803e32e0;
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e32e0) / lbl_803E3304);
  piVar5[3] = (int)lbl_803E3308;
  piVar5[6] = (int)(lbl_803E330C *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  if (param_3 == 0) {
    iVar2 = FUN_80017830(0x108,0x1a);
    *piVar5 = iVar2;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dc8d8,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 1;
    }
  }
  if (((int)*(short *)(param_2 + 0x20) != 0xffffffff) &&
     (uVar3 = GameBit_Get((int)*(short *)(param_2 + 0x20)), uVar3 != 0)) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ea20
 * EN v1.0 Address: 0x8014EA20
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x8014F320
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ea20(short *param_1,undefined4 *param_2)
{
  float fVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = (float *)*param_2;
  iVar2 = FUN_80006a10((double)(float)param_2[2],pfVar4);
  if ((((iVar2 != 0) || (pfVar4[4] != DAT_803de6e0)) &&
      (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)lbl_803E3310,*param_2,param_1,&DAT_803dc8e0,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 7) = *(byte *)(param_2 + 7) & 0xfe;
  }
  fVar1 = lbl_803E3314;
  DAT_803de6e0 = pfVar4[4];
  if ((*(byte *)(param_2 + 7) & 2) == 0) {
    *(float *)(param_1 + 0x12) =
         lbl_803E3314 * (pfVar4[0x1a] - *(float *)(param_1 + 6)) + *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * (pfVar4[0x1b] - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (pfVar4[0x1c] - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
  }
  else {
    *(float *)(param_1 + 0x12) =
         lbl_803E3314 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((lbl_803E3318 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = lbl_803E331C;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * lbl_803E331C;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (lbl_803E3320 < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = lbl_803E3320;
  }
  if (lbl_803E3320 < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = lbl_803E3320;
  }
  if (lbl_803E3320 < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = lbl_803E3320;
  }
  if (*(float *)(param_1 + 0x12) < lbl_803E3324) {
    *(float *)(param_1 + 0x12) = lbl_803E3324;
  }
  if (*(float *)(param_1 + 0x14) < lbl_803E3324) {
    *(float *)(param_1 + 0x14) = lbl_803E3324;
  }
  if (*(float *)(param_1 + 0x16) < lbl_803E3324) {
    *(float *)(param_1 + 0x16) = lbl_803E3324;
  }
  FUN_80017a88((double)(*(float *)(param_1 + 0x12) * lbl_803DC074),
               (double)(*(float *)(param_1 + 0x14) * lbl_803DC074),
               (double)(*(float *)(param_1 + 0x16) * lbl_803DC074),(int)param_1);
  *(short *)((int)param_2 + 0x1e) =
       *(short *)((int)param_2 + 0x1e) + (short)(int)(lbl_803E3328 * lbl_803DC074);
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(lbl_803E332C * lbl_803DC074);
  dVar5 = (double)FUN_80293f90();
  *param_1 = *param_1 + (short)(int)(lbl_803E3330 * (float)((double)lbl_803E3334 * dVar5));
  dVar5 = (double)FUN_80293f90();
  param_1[2] = param_1[2] + (short)(int)(lbl_803E3330 * (float)((double)lbl_803E3334 * dVar5));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ed98
 * EN v1.0 Address: 0x8014ED98
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8014F688
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ed98(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,3);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_80017814(uVar1);
    *puVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ede0
 * EN v1.0 Address: 0x8014EDE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014F6E0
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ede0(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014ede4
 * EN v1.0 Address: 0x8014EDE4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8014F988
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ede4(uint param_1,int param_2,int param_3)
{
  double dVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  
  dVar1 = DOUBLE_803e3340;
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e3340) / lbl_803E3364);
  piVar4[5] = (int)(lbl_803E3330 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  piVar4[6] = (int)lbl_803E334C;
  if (param_3 == 0) {
    iVar2 = FUN_80017830(0x108,0x1a);
    *piVar4 = iVar2;
    if (*piVar4 != 0) {
      FUN_800033a8(*piVar4,0,0x108);
    }
    cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar4[5],*piVar4,param_1,&DAT_803dc8e0,0xffffffff);
    if (cVar3 == '\0') {
      *(byte *)(piVar4 + 7) = *(byte *)(piVar4 + 7) | 1;
    }
    FUN_80006824(param_1,SFXfox_treadwater422);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void hagabon_release(void) {}
void hagabon_initialise(void) {}
void swarmbaddie_hitDetect(void) {}
void swarmbaddie_release(void) {}
void swarmbaddie_initialise(void) {}
void wispbaddie_hitDetect(void) {}

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, u16 sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void mm_free(void *p);
extern void objRenderFn_8003b8f4(f32);
extern void objParticleFn_80099d84(int obj, int p2, int p3, f32 f1, f32 f2);
extern f32 lbl_803E2608;
extern f32 lbl_803E260C;
extern f32 lbl_803E2610;
extern f32 lbl_803E2614;
extern f32 lbl_803E2618;
extern f32 lbl_803E261C;
extern f32 lbl_803E2620;
extern f32 lbl_803E2624;
extern f32 lbl_803E2628;
extern f32 lbl_803E262C;
extern f32 lbl_803E2630;
extern f32 lbl_803E2634;
extern f32 lbl_803E2638;
extern f32 lbl_803E263C;
extern f32 lbl_803E2650;
extern f32 lbl_803E2654;
extern f64 lbl_803E2640; /* int->float magic */
extern f64 lbl_803E2648; /* int->float magic */
extern f32 lbl_803E2658;
extern f32 lbl_803E265C;
extern f32 lbl_803E2660;
extern f32 lbl_803E2664;
extern f32 lbl_803E2668;
extern f32 lbl_803E266C;
extern f32 lbl_803E2670;
extern f32 lbl_803E2674;
extern f32 lbl_803E2678;
extern f32 lbl_803E267C;
extern f32 lbl_803E2680;
extern f32 lbl_803E2684;
extern f32 lbl_803E2688;
extern f32 lbl_803E268C;
extern f32 lbl_803E2690;
extern f32 lbl_803E2694;
extern f32 lbl_803E2698;
extern f32 lbl_803E269C;
extern f32 lbl_803E26A0;
extern f32 lbl_803E26A4;
extern f64 lbl_803E26A8; /* int->float magic */
extern f32 lbl_803E26B0;
extern f32 lbl_803E26B4;
extern f32 lbl_803E26B8;
extern f32 lbl_803E26BC;
extern f32 lbl_803E26C0;
extern f32 lbl_803E26C4;
extern f32 lbl_803E26C8;
extern f32 lbl_803E26CC;
extern f32 lbl_803E26D0;
extern f32 lbl_803E26D4;
extern f32 lbl_803E26D8;
extern f32 lbl_803E26DC;
extern f32 lbl_803E26E0;
extern f32 lbl_803E26E4;
extern f32 lbl_803E26E8;
extern f32 lbl_803E26EC;
extern f32 lbl_803E26F0;
extern f32 lbl_803E26F4;
extern f32 lbl_803E26F8;
extern f32 lbl_803E26FC;
extern f64 lbl_803E2700;
extern int lbl_803DBC78;
extern int lbl_803DBC80;
extern void *mmAlloc(int size, int heap, int flags);
extern void *memset(void *dst, int val, u32 n);
extern int *gRomCurveInterface;
extern int *gPartfxInterface;
extern int lbl_803DBC70;
extern int lbl_803DDA60;
extern int lbl_803DDA68;
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern MapEventInterface **gMapEventInterface;
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(void *a, void *b);
extern int Curve_AdvanceAlongPath(int curve, f32 t);
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void objLightFn_8009a1dc(int obj, f32 radius, void *pos, int type, int flags);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern int getAngle(f32 dx, f32 dz);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 moveStepScale, f32 deltaTime, void *events);
extern void Sfx_SetObjectChannelVolume(f32 volumeScale, int obj, int channel, int volume);

typedef union PressureSwitchIntToDouble {
    u64 bits;
    f64 value;
} PressureSwitchIntToDouble;

#define SWARMBADDIE_FLAG_PATH_NEEDS_LINK 0x01
#define SWARMBADDIE_FLAG_CHASE_PLAYER 0x02
#define SWARMBADDIE_FLAG_RETURN_TO_PATH 0x04

typedef struct SwarmBaddieState {
    int curve;
    int player;
    f32 curveStep;
    f32 playerDistance;
    f32 pathDistance;
    f32 chaseRadius;
    f32 hitVolumeEnvelope;
    u8 flags;
    u8 pad1d;
    s16 yawWavePhase;
    s16 rollWavePhase;
    u8 pad22[2];
} SwarmBaddieState;

#pragma scheduling off
#pragma peephole off
void fn_8014E1DC(int obj, int *state) {
    int curve;
    int player;
    int angleDelta;
    int angle;
    unsigned char *flags;
    char animEvents[32];
    f32 waveA;
    f32 waveB;
    f32 accel;
    f32 damp;
    f32 maxSpeed;
    f32 minSpeed;

    curve = state[0];
    flags = (unsigned char *)state + 0x26;

    if (((Curve_AdvanceAlongPath(curve, *(f32 *)(state + 2)) != 0) ||
         (*(int *)(curve + 0x10) != *(int *)&lbl_803DDA58)) &&
        ((*(int (**)(int))(*(int *)gRomCurveInterface + 0x90))(curve) != 0) &&
        ((*(int (**)(int, f32, int, int *, int))(*(int *)gRomCurveInterface + 0x8c))
             (state[0], lbl_803E2608, obj, &lbl_803DBC70, -1) != 0)) {
        *flags &= 0xfe;
    }

    *(int *)&lbl_803DDA58 = *(int *)(curve + 0x10);

    *(u16 *)((char *)state + 0x20) += (s16)(s32)(lbl_803E260C * timeDelta);
    *(u16 *)((char *)state + 0x22) += (s16)(s32)(lbl_803E2610 * timeDelta);
    *(u16 *)((char *)state + 0x24) += (s16)(s32)(lbl_803E2614 * timeDelta);

    waveA = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x22)) /
                        lbl_803E2620);
    waveB = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x20)) /
                        lbl_803E2620);
    *(s16 *)(obj + 4) = (s16)(s32)(lbl_803E2618 * (waveA + waveB));

    waveA = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x24)) /
                        lbl_803E2620);
    waveB = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x20)) /
                        lbl_803E2620);
    *(s16 *)(obj + 2) = (s16)(s32)(lbl_803E2618 * (waveA + waveB));

    accel = lbl_803E2624;
    if ((*flags & 2) != 0) {
        player = state[1];
        *(f32 *)(obj + 0x24) += accel * (*(f32 *)(player + 0xc) - *(f32 *)(obj + 0xc));
        *(f32 *)(obj + 0x28) += accel *
                                ((lbl_803E2628 + *(f32 *)(player + 0x10)) -
                                 *(f32 *)(obj + 0x10));
        *(f32 *)(obj + 0x2c) += accel * (*(f32 *)(player + 0x14) - *(f32 *)(obj + 0x14));
    } else if ((*flags & 4) != 0) {
        *(f32 *)(obj + 0x24) += accel * (*(f32 *)(curve + 0x68) - *(f32 *)(obj + 0xc));
        *(f32 *)(obj + 0x28) += accel * (*(f32 *)(curve + 0x6c) - *(f32 *)(obj + 0x10));
        *(f32 *)(obj + 0x2c) += accel * (*(f32 *)(curve + 0x70) - *(f32 *)(obj + 0x14));
    } else {
        *(f32 *)(obj + 0x24) += accel * (*(f32 *)(curve + 0x68) - *(f32 *)(obj + 0xc));
        waveA = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x22)) /
                            lbl_803E2620);
        waveB = fn_80293E80((lbl_803E261C * (f32)(u32)*(u16 *)((char *)state + 0x20)) /
                            lbl_803E2620);
        *(f32 *)(obj + 0x28) += accel *
                                (((lbl_803E262C * (waveA + waveB)) +
                                  *(f32 *)(curve + 0x6c)) -
                                 *(f32 *)(obj + 0x10));
        *(f32 *)(obj + 0x2c) += accel * (*(f32 *)(curve + 0x70) - *(f32 *)(obj + 0x14));
    }

    damp = lbl_803E2630;
    *(f32 *)(obj + 0x24) *= damp;
    *(f32 *)(obj + 0x28) *= damp;
    *(f32 *)(obj + 0x2c) *= damp;

    maxSpeed = lbl_803E2634;
    if (*(f32 *)(obj + 0x24) > maxSpeed) {
        *(f32 *)(obj + 0x24) = maxSpeed;
    }
    if (*(f32 *)(obj + 0x28) > maxSpeed) {
        *(f32 *)(obj + 0x28) = maxSpeed;
    }
    if (*(f32 *)(obj + 0x2c) > maxSpeed) {
        *(f32 *)(obj + 0x2c) = maxSpeed;
    }

    minSpeed = lbl_803E2638;
    if (*(f32 *)(obj + 0x24) < minSpeed) {
        *(f32 *)(obj + 0x24) = minSpeed;
    }
    if (*(f32 *)(obj + 0x28) < minSpeed) {
        *(f32 *)(obj + 0x28) = minSpeed;
    }
    if (*(f32 *)(obj + 0x2c) < minSpeed) {
        *(f32 *)(obj + 0x2c) = minSpeed;
    }

    objMove(obj,
            *(f32 *)(obj + 0x24) * timeDelta,
            *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);
    ObjAnim_AdvanceCurrentMove(obj, *(f32 *)(state + 3), timeDelta, animEvents);

    player = state[1];
    angle = (u16)getAngle(*(f32 *)(obj + 0x18) - *(f32 *)(player + 0x18),
                          *(f32 *)(obj + 0x20) - *(f32 *)(player + 0x20));
    angleDelta = angle - ((int)*(s16 *)obj & 0xffff);
    if (angleDelta > 0x8000) {
        angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xffff;
    }

    *(s16 *)obj += (s16)(s32)(((f32)angleDelta * timeDelta) / lbl_803E263C);
}

void hagabon_hitDetect(int obj) {
    if (*(u32 *)(*(int *)(obj + 0x54) + 0x50) != 0) {
        Sfx_PlayFromObject(obj, SFXand_swipe2);
    }
}
void swarmbaddie_free(int obj) {
    void **state = *(void ***)(obj + 0xB8);
    ObjGroup_RemoveObject(obj, 3);
    if (*state != NULL) {
        mm_free(*state);
        *state = NULL;
    }
}
void wispbaddie_free(int obj) {
    void **state = *(void ***)(obj + 0xB8);
    ObjGroup_RemoveObject(obj, 3);
    if (*state != NULL) {
        mm_free(*state);
        *state = NULL;
    }
}
void hagabon_free(int obj) {
    void **state = *(void ***)(obj + 0xB8);
    ObjGroup_RemoveObject(obj, 3);
    Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
    if (*state != NULL) {
        mm_free(*state);
        *state = NULL;
    }
}
void swarmbaddie_init(int obj, int data, int skip_alloc) {
    int state = *(int *)(obj + 0xB8);
    *(f32 *)(state + 8) = (f32)(s32)*(s16 *)(data + 0x1A) / lbl_803E26CC;
    *(f32 *)(state + 0x14) = lbl_803E2698 * (f32)(s32)*(s8 *)(data + 0x19);
    *(f32 *)(state + 0x18) = lbl_803E26B4;
    if (skip_alloc == 0) {
        *(void **)state = mmAlloc(0x108, 0x1A, 0);
        if (*(void **)state != NULL) {
            memset(*(void **)state, 0, 0x108);
        }
        if ((u8)(*(int (*)(void *, int, f32, void *, int))(*(int *)((int)*gRomCurveInterface + 0x8C)))
                (*(void **)state, obj, *(f32 *)(state + 0x14), &lbl_803DBC78, -1) == 0) {
            *(u8 *)(state + 0x1C) |= 0x1;
        }
        Sfx_PlayFromObject(obj, SFXfox_treadwater422);
    }
    *(u16 *)(obj + 0xB0) |= 0x2000;
}
void hagabon_init(int obj, int data, int skip_alloc) {
    int state = *(int *)(obj + 0xB8);
    *(f32 *)(state + 8) = (f32)(s32)*(s16 *)(data + 0x1A) / lbl_803E266C;
    *(f32 *)(state + 0xC) = lbl_803E2670;
    *(f32 *)(state + 0x18) = lbl_803E2674 * (f32)(s32)*(s8 *)(data + 0x19);
    if (skip_alloc == 0) {
        *(void **)state = mmAlloc(0x108, 0x1A, 0);
        if (*(void **)state != NULL) {
            memset(*(void **)state, 0, 0x108);
        }
        if ((u8)(*(int (*)(void *, int, f32, void *, int))(*(int *)((int)*gRomCurveInterface + 0x8C)))
                (*(void **)state, obj, *(f32 *)(state + 0x18), &lbl_803DBC70, -1) == 0) {
            *(u8 *)(state + 0x26) |= 0x1;
        }
    }
    if (*(s16 *)(data + 0x20) != -1) {
        if (GameBit_Get(*(s16 *)(data + 0x20)) != 0) {
            *(int *)(obj + 0xF4) = 1;
        }
    }
}
void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    int state = *(int *)(obj + 0xB8);
    s32 v = visible;
    if (v != 0) {
        if (*(int *)(obj + 0xF4) == 0) {
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)
                (obj, p2, p3, p4, p5, lbl_803E2650);
            if ((*(u8 *)(state + 0x26) & 0x10) != 0) {
                objParticleFn_80099d84(obj, 3, 0, lbl_803E2650,
                    (f32)(u32)*(u8 *)(obj + 0x36) / lbl_803E2654);
            }
            if ((*(u8 *)(state + 0x26) & 0x08) != 0) {
                objParticleFn_80099d84(obj, 4, 0, lbl_803E2650,
                    (f32)(u32)*(u8 *)(obj + 0x36) / lbl_803E2654);
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int hagabon_getExtraSize(void) { return 0x28; }
int hagabon_getObjectTypeId(void) { return 0xb; }
int swarmbaddie_getExtraSize(void) { return 0x24; }
int swarmbaddie_getObjectTypeId(void) { return 0x9; }
int wispbaddie_getExtraSize(void) { return 0x2c; }
int wispbaddie_getObjectTypeId(void) { return 0x9; }

#pragma peephole off
void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
void wispbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void fn_8014EE8C(int obj, SwarmBaddieState *state)
{
    int curve;
    int done;
    f32 step;
    f32 wave;

    curve = state->curve;
    done = Curve_AdvanceAlongPath(curve, state->curveStep);
    if (((done != 0) || (*(int *)(curve + 0x10) != lbl_803DDA60)) &&
        ((*(u8(**)(int))(*gRomCurveInterface + 0x90))(curve) != 0) &&
        ((*(u8(**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
             state->curve, obj, lbl_803E2678, &lbl_803DBC78, -1) != 0)) {
        state->flags &= ~SWARMBADDIE_FLAG_PATH_NEEDS_LINK;
    }
    lbl_803DDA60 = *(int *)(curve + 0x10);
    if ((state->flags & SWARMBADDIE_FLAG_CHASE_PLAYER) != 0) {
        step = lbl_803E267C;
        *(f32 *)(obj + 0x24) = step * (*(f32 *)(state->player + 0xc) - *(f32 *)(obj + 0xc)) +
                               *(f32 *)(obj + 0x24);
        *(f32 *)(obj + 0x28) =
            step * ((lbl_803E2680 + *(f32 *)(state->player + 0x10)) - *(f32 *)(obj + 0x10)) +
            *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x2c) = step * (*(f32 *)(state->player + 0x14) - *(f32 *)(obj + 0x14)) +
                               *(f32 *)(obj + 0x2c);
    } else {
        step = lbl_803E267C;
        *(f32 *)(obj + 0x24) = step * (*(f32 *)(curve + 0x68) - *(f32 *)(obj + 0xc)) +
                               *(f32 *)(obj + 0x24);
        *(f32 *)(obj + 0x28) = step * (*(f32 *)(curve + 0x6c) - *(f32 *)(obj + 0x10)) +
                               *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x2c) = step * (*(f32 *)(curve + 0x70) - *(f32 *)(obj + 0x14)) +
                               *(f32 *)(obj + 0x2c);
    }

    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) * (step = lbl_803E2684);
    *(f32 *)(obj + 0x28) *= step;
    *(f32 *)(obj + 0x2c) *= step;

    if (*(f32 *)(obj + 0x24) > lbl_803E2688) {
        *(f32 *)(obj + 0x24) = lbl_803E2688;
    }
    if (*(f32 *)(obj + 0x28) > lbl_803E2688) {
        *(f32 *)(obj + 0x28) = lbl_803E2688;
    }
    if (*(f32 *)(obj + 0x2c) > lbl_803E2688) {
        *(f32 *)(obj + 0x2c) = lbl_803E2688;
    }
    if (*(f32 *)(obj + 0x24) < lbl_803E268C) {
        *(f32 *)(obj + 0x24) = lbl_803E268C;
    }
    if (*(f32 *)(obj + 0x28) < lbl_803E268C) {
        *(f32 *)(obj + 0x28) = lbl_803E268C;
    }
    if (*(f32 *)(obj + 0x2c) < lbl_803E268C) {
        *(f32 *)(obj + 0x2c) = lbl_803E268C;
    }

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);

    state->yawWavePhase += (s16)(lbl_803E2690 * timeDelta);
    state->rollWavePhase += (s16)(lbl_803E2694 * timeDelta);

    *(s16 *)obj += (s16)(lbl_803E2698 *
                         (lbl_803E269C *
                          fn_80293E80((lbl_803E26A0 * (f32)state->yawWavePhase) / lbl_803E26A4)));

    *(s16 *)(obj + 4) += (s16)(lbl_803E2698 *
                               (lbl_803E269C *
                                fn_80293E80((lbl_803E26A0 * (f32)state->rollWavePhase) / lbl_803E26A4)));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8014F620(int obj, int *state)
{
    int curve;
    int done;
    f32 step;
    f32 wave;

    curve = state[0];
    *(s16 *)((u8 *)state + 0x26) += (s16)(lbl_803E26D0 * timeDelta);
    *(s16 *)(state + 10) += (s16)(lbl_803E26D4 * timeDelta);

    wave = lbl_803E26D8 + fn_80293E80((lbl_803E26DC * (f32)*(s16 *)((u8 *)state + 0x26)) /
                                      lbl_803E26E0);
    done = Curve_AdvanceAlongPath(curve, *(f32 *)(state + 2) * wave);
    if (((done != 0) || (*(int *)(curve + 0x10) != lbl_803DDA68)) &&
        ((*(u8(**)(int))(*gRomCurveInterface + 0x90))(curve) != 0) &&
        ((*(u8(**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
             state[0], obj, lbl_803E26E4, &lbl_803DBC80, -1) != 0)) {
        *(u8 *)((u8 *)state + 0x24) = *(u8 *)((u8 *)state + 0x24) & ~1;
    }
    lbl_803DDA68 = *(int *)(curve + 0x10);

    if ((*(u8 *)((u8 *)state + 0x24) & 2) != 0) {
        *(f32 *)(obj + 0x24) =
            lbl_803E26E8 * (*(f32 *)(state[1] + 0xc) - *(f32 *)(obj + 0xc)) +
            *(f32 *)(obj + 0x24);

        wave = fn_80293E80((lbl_803E26DC * (f32)*(s16 *)(state + 10)) /
                           lbl_803E26E0);
        *(f32 *)(obj + 0x28) =
            ((lbl_803E26F0 * wave + (lbl_803E26EC + *(f32 *)(state[1] + 0x10))) -
             *(f32 *)(obj + 0x10)) * lbl_803E26E8 +
            *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x2c) =
            lbl_803E26E8 * (*(f32 *)(state[1] + 0x14) - *(f32 *)(obj + 0x14)) +
            *(f32 *)(obj + 0x2c);
    } else {
        *(f32 *)(obj + 0x24) = lbl_803E26E8 * (*(f32 *)(curve + 0x68) - *(f32 *)(obj + 0xc)) +
                               *(f32 *)(obj + 0x24);

        wave = fn_80293E80((lbl_803E26DC * (f32)*(s16 *)(state + 10)) /
                           lbl_803E26E0);
        *(f32 *)(obj + 0x28) =
            ((lbl_803E26F0 * wave + *(f32 *)(curve + 0x6c)) - *(f32 *)(obj + 0x10)) *
                lbl_803E26E8 +
            *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x2c) = lbl_803E26E8 * (*(f32 *)(curve + 0x70) - *(f32 *)(obj + 0x14)) +
                               *(f32 *)(obj + 0x2c);
    }

    *(f32 *)(obj + 0x24) = *(f32 *)(obj + 0x24) * (step = lbl_803E26F4);
    *(f32 *)(obj + 0x28) *= step;
    *(f32 *)(obj + 0x2c) *= step;

    if (*(f32 *)(obj + 0x24) > lbl_803E26F8) {
        *(f32 *)(obj + 0x24) = lbl_803E26F8;
    }
    if (*(f32 *)(obj + 0x28) > lbl_803E26F8) {
        *(f32 *)(obj + 0x28) = lbl_803E26F8;
    }
    if (*(f32 *)(obj + 0x2c) > lbl_803E26F8) {
        *(f32 *)(obj + 0x2c) = lbl_803E26F8;
    }
    if (*(f32 *)(obj + 0x24) < lbl_803E26FC) {
        *(f32 *)(obj + 0x24) = lbl_803E26FC;
    }
    if (*(f32 *)(obj + 0x28) < lbl_803E26FC) {
        *(f32 *)(obj + 0x28) = lbl_803E26FC;
    }
    if (*(f32 *)(obj + 0x2c) < lbl_803E26FC) {
        *(f32 *)(obj + 0x2c) = lbl_803E26FC;
    }

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
            *(f32 *)(obj + 0x2c) * timeDelta);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void swarmbaddie_update(int obj)
{
    int hitObj;
    int *state;
    f32 d[3];
    f32 sqz;
    f32 sqx;
    f32 sqy;
    f32 volume;
    int oldTarget;
    int hitD;
    int hitE;
    int hitC;
    int hitF;
    int hitB;
    int hitA;

    state = *(int **)(obj + 0xb8);
    oldTarget = state[0];
    if (ObjHits_GetPriorityHitWithPosition(obj, &hitD, &hitB, &hitA, &hitE, &hitC, &hitF) != 0) {
        *(f32 *)(state + 6) = lbl_803E26B0;
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    ObjHits_EnableObject(obj);
    if (*(f32 *)(state + 6) > lbl_803E26B4) {
        *(f32 *)(state + 6) = *(f32 *)(state + 6) - lbl_803E26B8;
    }
    volume = *(f32 *)(state + 6);
    Sfx_SetObjectChannelVolume(
        lbl_803E26C0 * fn_80293E80((lbl_803E26A0 *
                                    (f32)(*(s16 *)((u8 *)state + 0x1e) + *(s16 *)(state + 8))) /
                                   lbl_803E26A4) +
            volume,
        obj, 0x40, (int)(lbl_803E26BC * volume));
    (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 0x336, 0, 2, -1,
                                                                       (int)(state + 6));
    state[1] = Obj_GetPlayerObject();
    if (*(void **)(state + 1) != NULL) {
        d[0] = *(f32 *)(state[1] + 0x18) - *(f32 *)(obj + 0x18);
        d[1] = *(f32 *)(state[1] + 0x1c) - *(f32 *)(obj + 0x1c);
        d[2] = *(f32 *)(state[1] + 0x20) - *(f32 *)(obj + 0x20);
        sqz = d[2] * d[2];
        sqx = d[0] * d[0];
        sqy = d[1] * d[1];
        *(f32 *)(state + 3) = sqrtf(sqz + (sqx + sqy));
    }
    if ((void *)oldTarget != NULL) {
        d[0] = *(f32 *)(oldTarget + 0x68) - *(f32 *)(obj + 0x18);
        d[1] = *(f32 *)(oldTarget + 0x6c) - *(f32 *)(obj + 0x1c);
        d[2] = *(f32 *)(oldTarget + 0x70) - *(f32 *)(obj + 0x20);
        sqz = d[2] * d[2];
        sqx = d[0] * d[0];
        sqy = d[1] * d[1];
        *(f32 *)(state + 4) = sqrtf(sqz + (sqx + sqy));
    }
    if (((*(u8 *)(state + 7) & 2) != 0) && (*(f32 *)(state + 4) > lbl_803E26C4)) {
        *(u8 *)(state + 7) = *(u8 *)(state + 7) & ~2;
        *(u8 *)(state + 7) = *(u8 *)(state + 7) | 4;
    }
    if (((*(u8 *)(state + 7) & 4) != 0) && (*(f32 *)(state + 4) < lbl_803E26C8)) {
        *(u8 *)(state + 7) = *(u8 *)(state + 7) & ~4;
    }
    if (((*(u8 *)(state + 7) & 6) == 0) && (*(void **)(state + 1) != NULL) &&
        (*(f32 *)(state + 3) < *(f32 *)(state + 5))) {
        *(u8 *)(state + 7) = *(u8 *)(state + 7) | 2;
    }
    fn_8014EE8C(obj, (SwarmBaddieState *)state);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hagabon_update(int obj)
{
    int player;
    int data;
    int oldCurve;
    int *state;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;
    int hitA;
    int hitB;
    int hitC;
    f32 lightPos[3];
    f32 hitX;
    f32 hitZ;
    int fade;
    PressureSwitchIntToDouble fadeAsDouble;
    PressureSwitchIntToDouble eventAsDouble;

    state = *(int **)(obj + 0xb8);
    oldCurve = state[0];
    data = *(int *)(obj + 0x4c);

    if (*(int *)(obj + 0xf4) != 0) {
        if ((*(s16 *)(data + 0x20) != -1) && (GameBit_Get(*(s16 *)(data + 0x20)) != 0)) {
            return;
        }
        if ((*(int (**)(int))(*(int *)gMapEventInterface + 0x68))(*(int *)(data + 0x14)) == 0) {
            return;
        }
        *(int *)(obj + 0xf4) = 0;
        *(u8 *)(obj + 0x36) = 1;
        *(u8 *)((u8 *)state + 0x26) |= 8;
        Sfx_PlayFromObject(obj, SFXfox_treadwater122);
        return;
    }

    player = Obj_GetPlayerObject();
    dist = Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18));
    if (dist < lbl_803E2658) {
        Sfx_PlayFromObject(obj, SFXstaff_proj_outofmagic);
    } else if (dist > lbl_803E265C) {
        Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
    }

    if ((*(u8 *)(obj + 0x36) != 0) && ((*(u8 *)((u8 *)state + 0x26) & 0x18) != 0)) {
        if ((*(u8 *)((u8 *)state + 0x26) & 0x10) != 0) {
            fadeAsDouble.bits = CONCAT44(0x43300000, (u32)*(u8 *)(obj + 0x36));
            fade = (int)((f32)(fadeAsDouble.value - lbl_803E2640) - timeDelta);
            *(u8 *)(obj + 0x36) = (u8)fade;
            if (*(u8 *)(obj + 0x36) < 7) {
                *(int *)(obj + 0xf4) = 1;
                *(u8 *)(obj + 0x36) = 0;
                *(u8 *)((u8 *)state + 0x26) &= 0xef;
                Sfx_StopFromObject(obj, SFXstaff_proj_outofmagic);
            }
            ObjHits_DisableObject(obj);
        }
        if ((*(u8 *)((u8 *)state + 0x26) & 8) != 0) {
            fadeAsDouble.bits = CONCAT44(0x43300000, (u32)*(u8 *)(obj + 0x36));
            fade = (int)((f32)(fadeAsDouble.value - lbl_803E2640) + timeDelta);
            *(u8 *)(obj + 0x36) = (u8)fade;
            if (*(u8 *)(obj + 0x36) > 0xf8) {
                *(u8 *)(obj + 0x36) = 0xff;
                *(u8 *)((u8 *)state + 0x26) &= 0xf7;
            }
        }
    } else {
        if (ObjHits_GetPriorityHitWithPosition(obj, &hitA, &hitB, &hitC, &hitX, &lightPos[1],
                                               &hitZ) != 0) {
            Sfx_StopObjectChannel(obj, 0x7f);
            *(u8 *)((u8 *)state + 0x26) |= 0x10;
            Sfx_PlayFromObject(obj, SFXdoor_unlocked);
            Sfx_PlayFromObject(obj, SFXdoor_creak);
            Sfx_PlayFromObject(obj, SFXfox_treadwater222);
            Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            hitX += playerMapOffsetX;
            hitZ += playerMapOffsetZ;
            lightPos[0] = hitX;
            lightPos[2] = hitZ;
            objLightFn_8009a1dc(obj, lbl_803E2660, lightPos, 3, 0);
            eventAsDouble.bits = CONCAT44(0x43300000,
                                          (s32)(*(s16 *)(data + 0x1c) * 0x3c) ^ 0x80000000);
            (*(void (**)(int, f32))(*(int *)gMapEventInterface + 0x64))(
                *(int *)(data + 0x14), (f32)(eventAsDouble.value - lbl_803E2648));
            if (*(s16 *)(data + 0x20) != -1) {
                GameBit_Set(*(s16 *)(data + 0x20), 1);
            }
        }
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
    }

    player = Obj_GetPlayerObject();
    state[1] = player;
    if (player != 0) {
        dx = *(f32 *)(player + 0x18) - *(f32 *)(obj + 0x18);
        dy = *(f32 *)(player + 0x1c) - *(f32 *)(obj + 0x1c);
        dz = *(f32 *)(player + 0x20) - *(f32 *)(obj + 0x20);
        *(f32 *)(state + 4) = sqrtf(dz * dz + dx * dx + dy * dy);
    }
    if (oldCurve != 0) {
        dx = *(f32 *)(oldCurve + 0x68) - *(f32 *)(obj + 0x18);
        dy = *(f32 *)(oldCurve + 0x6c) - *(f32 *)(obj + 0x1c);
        dz = *(f32 *)(oldCurve + 0x70) - *(f32 *)(obj + 0x20);
        *(f32 *)(state + 5) = sqrtf(dz * dz + dx * dx + dy * dy);
    }
    if (((*(u8 *)((u8 *)state + 0x26) & 2) != 0) && (lbl_803E2664 < *(f32 *)(state + 5))) {
        *(u8 *)((u8 *)state + 0x26) &= 0xfd;
        *(u8 *)((u8 *)state + 0x26) |= 4;
    }
    if (((*(u8 *)((u8 *)state + 0x26) & 4) != 0) && (*(f32 *)(state + 5) < lbl_803E2668)) {
        *(u8 *)((u8 *)state + 0x26) &= 0xfb;
    }
    if (((*(u8 *)((u8 *)state + 0x26) & 6) == 0) && (*(s16 *)(data + 0x1e) == 0) &&
        (state[1] != 0) && (*(f32 *)(state + 4) < *(f32 *)(state + 6))) {
        *(u8 *)((u8 *)state + 0x26) |= 2;
    }
    fn_8014E1DC(obj, state);
}
#pragma peephole reset
#pragma scheduling reset

extern void hagabon_free(int obj);
extern void hagabon_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
extern void hagabon_hitDetect(int obj);
extern void hagabon_init(int obj, int data, int skip_alloc);
extern void swarmbaddie_free(int obj);
extern void swarmbaddie_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
extern void swarmbaddie_init(int obj, int data, int skip_alloc);

ObjectDescriptor gHagabonObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)hagabon_initialise,
    (ObjectDescriptorCallback)hagabon_release,
    0,
    (ObjectDescriptorCallback)hagabon_init,
    (ObjectDescriptorCallback)hagabon_update,
    (ObjectDescriptorCallback)hagabon_hitDetect,
    (ObjectDescriptorCallback)hagabon_render,
    (ObjectDescriptorCallback)hagabon_free,
    (ObjectDescriptorCallback)hagabon_getObjectTypeId,
    hagabon_getExtraSize,
};

ObjectDescriptor gSwarmBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)swarmbaddie_initialise,
    (ObjectDescriptorCallback)swarmbaddie_release,
    0,
    (ObjectDescriptorCallback)swarmbaddie_init,
    (ObjectDescriptorCallback)swarmbaddie_update,
    (ObjectDescriptorCallback)swarmbaddie_hitDetect,
    (ObjectDescriptorCallback)swarmbaddie_render,
    (ObjectDescriptorCallback)swarmbaddie_free,
    (ObjectDescriptorCallback)swarmbaddie_getObjectTypeId,
    swarmbaddie_getExtraSize,
};
