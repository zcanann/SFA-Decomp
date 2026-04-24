#include "ghidra_import.h"
#include "main/dll/pressureSwitch.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000b844();
extern undefined4 FUN_8000b8a8();
extern undefined4 FUN_8000bb38();
extern int FUN_80010340();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800217c8();
extern uint FUN_80021884();
extern undefined4 FUN_800238c4();
extern int FUN_80023d8c();
extern undefined4 FUN_8002ba34();
extern int FUN_8002bac4();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036868();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8009a010();
extern undefined4 FUN_8009a468();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();

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
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e32a0;
extern f32 FLOAT_803e32a4;
extern f32 FLOAT_803e32a8;
extern f32 FLOAT_803e32ac;
extern f32 FLOAT_803e32b0;
extern f32 FLOAT_803e32bc;
extern f32 FLOAT_803e32c0;
extern f32 FLOAT_803e32c4;
extern f32 FLOAT_803e32c8;
extern f32 FLOAT_803e32cc;
extern f32 FLOAT_803e32d0;
extern f32 FLOAT_803e32d4;
extern f32 FLOAT_803e32e8;
extern f32 FLOAT_803e32ec;
extern f32 FLOAT_803e32f0;
extern f32 FLOAT_803e32f4;
extern f32 FLOAT_803e32fc;
extern f32 FLOAT_803e3300;
extern f32 FLOAT_803e3304;
extern f32 FLOAT_803e3308;
extern f32 FLOAT_803e330c;
extern f32 FLOAT_803e3310;
extern f32 FLOAT_803e3314;
extern f32 FLOAT_803e3318;
extern f32 FLOAT_803e331c;
extern f32 FLOAT_803e3320;
extern f32 FLOAT_803e3324;
extern f32 FLOAT_803e3328;
extern f32 FLOAT_803e332c;
extern f32 FLOAT_803e3330;
extern f32 FLOAT_803e3334;
extern f32 FLOAT_803e3348;
extern f32 FLOAT_803e334c;
extern f32 FLOAT_803e3350;
extern f32 FLOAT_803e3354;
extern f32 FLOAT_803e3358;
extern f32 FLOAT_803e335c;
extern f32 FLOAT_803e3360;
extern f32 FLOAT_803e3364;

/*
 * --INFO--
 *
 * Function: FUN_8014e604
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
    FUN_80013e4c(DAT_803de6d0);
    DAT_803de6d0 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e638
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
    DAT_803de6d0 = FUN_80013ee8(0x5a);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014e670
 * EN v1.0 Address: 0x8014E244
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014E670
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014e670()
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014ebd8
 * EN v1.0 Address: 0x8014E248
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8014EBD8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ebd8(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  FUN_8000b844(param_1,0x236);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
    *puVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ec38
 * EN v1.0 Address: 0x8014E2A8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8014EC38
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ec38(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
    if ((*(byte *)(iVar1 + 0x26) & 0x10) != 0) {
      FUN_8009a010((double)FLOAT_803e32e8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / FLOAT_803e32ec),param_1,3,(int *)0x0);
    }
    if ((*(byte *)(iVar1 + 0x26) & 8) != 0) {
      FUN_8009a010((double)FLOAT_803e32e8,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e32d8) / FLOAT_803e32ec),param_1,4,(int *)0x0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ed20
 * EN v1.0 Address: 0x8014E374
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8014ED20
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ed20(uint param_1)
{
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    FUN_8000bb38(param_1,0x32b);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ed54
 * EN v1.0 Address: 0x8014E3A8
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x8014ED54
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ed54(ushort *param_1)
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
    iVar2 = FUN_8002bac4();
    dVar6 = (double)FUN_800217c8((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18));
    if ((double)FLOAT_803e32f0 <= dVar6) {
      if ((double)FLOAT_803e32f4 < dVar6) {
        FUN_8000b844((int)param_1,0x236);
      }
    }
    else {
      FUN_8000bb38((uint)param_1,0x236);
    }
    if ((*(byte *)(param_1 + 0x1b) == 0) || ((*(byte *)((int)piVar5 + 0x26) & 0x18) == 0)) {
      iVar2 = FUN_80036868((int)param_1,&uStack_50,&iStack_54,&uStack_58,&local_34,&uStack_30,
                           &local_2c);
      if (iVar2 != 0) {
        FUN_8000b7dc((int)param_1,0x7f);
        *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 0x10;
        FUN_8000bb38((uint)param_1,0x232);
        FUN_8000bb38((uint)param_1,0x233);
        FUN_8000bb38((uint)param_1,0x238);
        FUN_8000bb38((uint)param_1,0x1f2);
        local_34 = local_34 + FLOAT_803dda58;
        local_2c = local_2c + FLOAT_803dda5c;
        FUN_8009a468(param_1,auStack_40,3,(int *)0x0);
        local_20 = (double)CONCAT44(0x43300000,*(short *)(iVar3 + 0x1c) * 0x3c ^ 0x80000000);
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(float)(local_20 - DOUBLE_803e32e0),*(undefined4 *)(iVar3 + 0x14));
        if ((int)*(short *)(iVar3 + 0x20) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(iVar3 + 0x20),1);
        }
      }
      FUN_80035eec((int)param_1,10,1,0);
      FUN_80036018((int)param_1);
    }
    else {
      if ((*(byte *)((int)piVar5 + 0x26) & 0x10) != 0) {
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_28 - DOUBLE_803e32d8) - FLOAT_803dc074);
        local_20 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (*(byte *)(param_1 + 0x1b) < 7) {
          param_1[0x7a] = 0;
          param_1[0x7b] = 1;
          *(undefined *)(param_1 + 0x1b) = 0;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xef;
          FUN_8000b844((int)param_1,0x236);
        }
        FUN_80035ff8((int)param_1);
      }
      if ((*(byte *)((int)piVar5 + 0x26) & 8) != 0) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        iVar2 = (int)((float)(local_20 - DOUBLE_803e32d8) + FLOAT_803dc074);
        local_28 = (double)(longlong)iVar2;
        *(char *)(param_1 + 0x1b) = (char)iVar2;
        if (0xf8 < *(byte *)(param_1 + 0x1b)) {
          *(undefined *)(param_1 + 0x1b) = 0xff;
          *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xf7;
        }
      }
    }
    iVar2 = FUN_8002bac4();
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
    if (((*(byte *)((int)piVar5 + 0x26) & 2) != 0) && (FLOAT_803e32fc < (float)piVar5[5])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfd;
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 4;
    }
    if (((*(byte *)((int)piVar5 + 0x26) & 4) != 0) && ((float)piVar5[5] < FLOAT_803e3300)) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) & 0xfb;
    }
    if (((((*(byte *)((int)piVar5 + 0x26) & 6) == 0) && (*(short *)(iVar3 + 0x1e) == 0)) &&
        (piVar5[1] != 0)) && ((float)piVar5[4] < (float)piVar5[6])) {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 2;
    }
    FUN_8014e670(param_1,piVar5);
  }
  else if ((((int)*(short *)(iVar3 + 0x20) == 0xffffffff) ||
           (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x20)), uVar1 == 0)) &&
          (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0))
  {
    param_1[0x7a] = 0;
    param_1[0x7b] = 0;
    *(undefined *)(param_1 + 0x1b) = 1;
    *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 8;
    FUN_8000bb38((uint)param_1,0x237);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014f1e4
 * EN v1.0 Address: 0x8014E898
 * EN v1.0 Size: 392b
 * EN v1.1 Address: 0x8014F1E4
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014f1e4(int param_1,int param_2,int param_3)
{
  double dVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  int *piVar5;
  
  dVar1 = DOUBLE_803e32e0;
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e32e0) / FLOAT_803e3304);
  piVar5[3] = (int)FLOAT_803e3308;
  piVar5[6] = (int)(FLOAT_803e330c *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  if (param_3 == 0) {
    iVar2 = FUN_80023d8c(0x108,0x1a);
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
     (uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x20)), uVar3 != 0)) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014f320
 * EN v1.0 Address: 0x8014EA20
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x8014F320
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014f320(short *param_1,undefined4 *param_2)
{
  float fVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = (float *)*param_2;
  iVar2 = FUN_80010340((double)(float)param_2[2],pfVar4);
  if ((((iVar2 != 0) || (pfVar4[4] != DAT_803de6e0)) &&
      (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3310,*param_2,param_1,&DAT_803dc8e0,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 7) = *(byte *)(param_2 + 7) & 0xfe;
  }
  fVar1 = FLOAT_803e3314;
  DAT_803de6e0 = pfVar4[4];
  if ((*(byte *)(param_2 + 7) & 2) == 0) {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e3314 * (pfVar4[0x1a] - *(float *)(param_1 + 6)) + *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * (pfVar4[0x1b] - *(float *)(param_1 + 8)) + *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (pfVar4[0x1c] - *(float *)(param_1 + 10)) + *(float *)(param_1 + 0x16);
  }
  else {
    *(float *)(param_1 + 0x12) =
         FLOAT_803e3314 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 6)) +
         *(float *)(param_1 + 0x12);
    *(float *)(param_1 + 0x14) =
         fVar1 * ((FLOAT_803e3318 + *(float *)(param_2[1] + 0x10)) - *(float *)(param_1 + 8)) +
         *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x16) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 10)) +
         *(float *)(param_1 + 0x16);
  }
  fVar1 = FLOAT_803e331c;
  *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e331c;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar1;
  *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar1;
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x12)) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3320;
  }
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x14)) {
    *(float *)(param_1 + 0x14) = FLOAT_803e3320;
  }
  if (FLOAT_803e3320 < *(float *)(param_1 + 0x16)) {
    *(float *)(param_1 + 0x16) = FLOAT_803e3320;
  }
  if (*(float *)(param_1 + 0x12) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3324;
  }
  if (*(float *)(param_1 + 0x14) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x14) = FLOAT_803e3324;
  }
  if (*(float *)(param_1 + 0x16) < FLOAT_803e3324) {
    *(float *)(param_1 + 0x16) = FLOAT_803e3324;
  }
  FUN_8002ba34((double)(*(float *)(param_1 + 0x12) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803dc074),(int)param_1);
  *(short *)((int)param_2 + 0x1e) =
       *(short *)((int)param_2 + 0x1e) + (short)(int)(FLOAT_803e3328 * FLOAT_803dc074);
  *(short *)(param_2 + 8) = *(short *)(param_2 + 8) + (short)(int)(FLOAT_803e332c * FLOAT_803dc074);
  dVar5 = (double)FUN_802945e0();
  *param_1 = *param_1 + (short)(int)(FLOAT_803e3330 * (float)((double)FLOAT_803e3334 * dVar5));
  dVar5 = (double)FUN_802945e0();
  param_1[2] = param_1[2] + (short)(int)(FLOAT_803e3330 * (float)((double)FLOAT_803e3334 * dVar5));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014f688
 * EN v1.0 Address: 0x8014ED98
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8014F688
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014f688(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_800238c4(uVar1);
    *puVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014f6e0
 * EN v1.0 Address: 0x8014EDE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014F6E0
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014f6e0(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014f988
 * EN v1.0 Address: 0x8014EDE4
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x8014F988
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014f988(uint param_1,int param_2,int param_3)
{
  double dVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  
  dVar1 = DOUBLE_803e3340;
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e3340) / FLOAT_803e3364);
  piVar4[5] = (int)(FLOAT_803e3330 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  piVar4[6] = (int)FLOAT_803e334c;
  if (param_3 == 0) {
    iVar2 = FUN_80023d8c(0x108,0x1a);
    *piVar4 = iVar2;
    if (*piVar4 != 0) {
      FUN_800033a8(*piVar4,0,0x108);
    }
    cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar4[5],*piVar4,param_1,&DAT_803dc8e0,0xffffffff);
    if (cVar3 == '\0') {
      *(byte *)(piVar4 + 7) = *(byte *)(piVar4 + 7) | 1;
    }
    FUN_8000bb38(param_1,0x23a);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}
