#include "ghidra_import.h"
#include "main/dll/pressureSwitch.h"

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
  FUN_80006810(param_1,0x236);
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
void FUN_8014e2a8(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
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
    FUN_80006824(param_1,0x32b);
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
        FUN_80006810((int)param_1,0x236);
      }
    }
    else {
      FUN_80006824((uint)param_1,0x236);
    }
    if ((*(byte *)(param_1 + 0x1b) == 0) || ((*(byte *)((int)piVar5 + 0x26) & 0x18) == 0)) {
      iVar2 = ObjHits_GetPriorityHitWithPosition((int)param_1,&uStack_50,&iStack_54,&uStack_58,&local_34,&uStack_30,
                           &local_2c);
      if (iVar2 != 0) {
        FUN_8000680c((int)param_1,0x7f);
        *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 0x10;
        FUN_80006824((uint)param_1,0x232);
        FUN_80006824((uint)param_1,0x233);
        FUN_80006824((uint)param_1,0x238);
        FUN_80006824((uint)param_1,0x1f2);
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
          FUN_80006810((int)param_1,0x236);
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
    FUN_80006824((uint)param_1,0x237);
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
    FUN_80006824(param_1,0x23a);
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

/* 8b "li r3, N; blr" returners. */
int hagabon_getExtraSize(void) { return 0x28; }
int hagabon_func08(void) { return 0xb; }
int swarmbaddie_getExtraSize(void) { return 0x24; }
int swarmbaddie_func08(void) { return 0x9; }
int wispbaddie_getExtraSize(void) { return 0x2c; }
int wispbaddie_func08(void) { return 0x9; }

extern void hagabon_free(void);
extern void hagabon_render(void);
extern void hagabon_hitDetect(void);
extern void hagabon_update(void);
extern void hagabon_init(void);
extern void swarmbaddie_free(void);
extern void swarmbaddie_render(void);
extern void swarmbaddie_update(void);
extern void swarmbaddie_init(void);

u32 gHagabonObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)hagabon_initialise,
    (u32)hagabon_release,
    0,
    (u32)hagabon_init,
    (u32)hagabon_update,
    (u32)hagabon_hitDetect,
    (u32)hagabon_render,
    (u32)hagabon_free,
    (u32)hagabon_func08,
    (u32)hagabon_getExtraSize,
};

u32 gSwarmBaddieObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)swarmbaddie_initialise,
    (u32)swarmbaddie_release,
    0,
    (u32)swarmbaddie_init,
    (u32)swarmbaddie_update,
    (u32)swarmbaddie_hitDetect,
    (u32)swarmbaddie_render,
    (u32)swarmbaddie_free,
    (u32)swarmbaddie_func08,
    (u32)swarmbaddie_getExtraSize,
};
