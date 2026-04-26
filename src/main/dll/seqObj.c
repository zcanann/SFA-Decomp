#include "ghidra_import.h"
#include "main/dll/seqObj.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006820();
extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern uint FUN_80017760();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_800305c4();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_800360f0();
extern int FUN_800368c4();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern undefined4 FUN_80151844();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feac;
extern undefined4 DAT_8031fead;
extern undefined4 DAT_803dc8e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de6e8;
extern f64 DOUBLE_803e3398;
extern f64 DOUBLE_803e33f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e3368;
extern f32 FLOAT_803e336c;
extern f32 FLOAT_803e3370;
extern f32 FLOAT_803e337c;
extern f32 FLOAT_803e3380;
extern f32 FLOAT_803e3384;
extern f32 FLOAT_803e3388;
extern f32 FLOAT_803e338c;
extern f32 FLOAT_803e3390;
extern f32 FLOAT_803e3394;
extern f32 FLOAT_803e33a0;
extern f32 FLOAT_803e33a4;
extern f32 FLOAT_803e33a8;
extern f32 FLOAT_803e33ac;
extern f32 FLOAT_803e33b0;
extern f32 FLOAT_803e33b4;
extern f32 FLOAT_803e33b8;
extern f32 FLOAT_803e33c0;
extern f32 FLOAT_803e33c4;
extern f32 FLOAT_803e33c8;
extern f32 FLOAT_803e33cc;
extern f32 FLOAT_803e33d0;
extern f32 FLOAT_803e33d4;
extern f32 FLOAT_803e33d8;
extern f32 FLOAT_803e33dc;
extern f32 FLOAT_803e33e0;
extern f32 FLOAT_803e33e4;
extern f32 FLOAT_803e33e8;
extern f32 FLOAT_803e33ec;
extern void* PTR_DAT_8031fdc4;

/*
 * --INFO--
 *
 * Function: wispbaddie_update
 * EN v1.0 Address: 0x8014F9E8
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x8014FAB4
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wispbaddie_update(int param_1,undefined4 *param_2)
{
  float fVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double dVar5;
  
  pfVar4 = (float *)*param_2;
  *(short *)((int)param_2 + 0x26) =
       *(short *)((int)param_2 + 0x26) + (short)(int)(FLOAT_803e3368 * FLOAT_803dc074);
  *(short *)(param_2 + 10) =
       *(short *)(param_2 + 10) + (short)(int)(FLOAT_803e336c * FLOAT_803dc074);
  dVar5 = (double)FUN_80293f90();
  iVar2 = FUN_80006a10((double)((float)param_2[2] * (float)((double)FLOAT_803e3370 + dVar5)),pfVar4)
  ;
  if ((((iVar2 != 0) || (pfVar4[4] != DAT_803de6e8)) &&
      (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e337c,*param_2,param_1,&DAT_803dc8e8,0xffffffff),
     cVar3 != '\0')) {
    *(byte *)(param_2 + 9) = *(byte *)(param_2 + 9) & 0xfe;
  }
  DAT_803de6e8 = pfVar4[4];
  if ((*(byte *)(param_2 + 9) & 2) == 0) {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e3380 * (pfVar4[0x1a] - *(float *)(param_1 + 0xc)) + *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_80293f90();
    fVar1 = FLOAT_803e3380;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e3380 *
         ((float)((double)FLOAT_803e3388 * dVar5 + (double)pfVar4[0x1b]) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (pfVar4[0x1c] - *(float *)(param_1 + 0x14)) + *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x24) =
         FLOAT_803e3380 * (*(float *)(param_2[1] + 0xc) - *(float *)(param_1 + 0xc)) +
         *(float *)(param_1 + 0x24);
    dVar5 = (double)FUN_80293f90();
    fVar1 = FLOAT_803e3380;
    *(float *)(param_1 + 0x28) =
         FLOAT_803e3380 *
         ((float)((double)FLOAT_803e3388 * dVar5 +
                 (double)(FLOAT_803e3384 + *(float *)(param_2[1] + 0x10))) -
         *(float *)(param_1 + 0x10)) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x2c) =
         fVar1 * (*(float *)(param_2[1] + 0x14) - *(float *)(param_1 + 0x14)) +
         *(float *)(param_1 + 0x2c);
  }
  fVar1 = FLOAT_803e338c;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e338c;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x24)) {
    *(float *)(param_1 + 0x24) = FLOAT_803e3390;
  }
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x28)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e3390;
  }
  if (FLOAT_803e3390 < *(float *)(param_1 + 0x2c)) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e3390;
  }
  if (*(float *)(param_1 + 0x24) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x24) = FLOAT_803e3394;
  }
  if (*(float *)(param_1 + 0x28) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x28) = FLOAT_803e3394;
  }
  if (*(float *)(param_1 + 0x2c) < FLOAT_803e3394) {
    *(float *)(param_1 + 0x2c) = FLOAT_803e3394;
  }
  FUN_80017a88((double)(*(float *)(param_1 + 0x24) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x28) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803dc074),param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014fd38
 * EN v1.0 Address: 0x8014FD38
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8014FE24
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd38(int param_1)
{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  FUN_80037180(param_1,3);
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
 * Function: FUN_8014fd80
 * EN v1.0 Address: 0x8014FD80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014FE7C
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd80(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014fd84
 * EN v1.0 Address: 0x8014FD84
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8015025C
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fd84(uint param_1,int param_2,int param_3)
{
  float fVar1;
  double dVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  
  dVar2 = DOUBLE_803e3398;
  piVar5 = *(int **)(param_1 + 0xb8);
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e3398) / FLOAT_803e33b4;
  piVar5[3] = (int)fVar1;
  piVar5[2] = (int)fVar1;
  piVar5[6] = (int)(FLOAT_803e33b8 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar2));
  piVar5[8] = 0x337;
  if (param_3 == 0) {
    iVar3 = FUN_80017830(0x108,0x1a);
    *piVar5 = iVar3;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dc8e8,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)(piVar5 + 9) = *(byte *)(piVar5 + 9) | 1;
    }
    FUN_80006824(param_1,0x23b);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014fef8
 * EN v1.0 Address: 0x8014FEF8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8015038C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014fef8(undefined4 param_1,int param_2,undefined4 param_3,int param_4)
{
  if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    return;
  }
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff20
 * EN v1.0 Address: 0x8014FF20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801503B4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff20(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff24
 * EN v1.0 Address: 0x8014FF24
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801503B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff24(short *param_1,undefined4 param_2)
{
  FUN_8014d3d0(param_1,param_2,0xf,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ff4c
 * EN v1.0 Address: 0x8014FF4C
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801503EC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ff4c(undefined4 param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e33c0;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x80;
  *(float *)(param_2 + 0x308) = FLOAT_803e33c4;
  *(float *)(param_2 + 0x300) = FLOAT_803e33c8;
  *(float *)(param_2 + 0x304) = FLOAT_803e33cc;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e33d0;
  *(float *)(param_2 + 0x314) = FLOAT_803e33d0;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = FLOAT_803e33d4;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ffa8
 * EN v1.0 Address: 0x8014FFA8
 * EN v1.0 Size: 1176b
 * EN v1.1 Address: 0x80150448
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ffa8(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286840();
  fVar3 = FLOAT_803e33d8;
  psVar5 = (short *)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  puVar8 = (&PTR_DAT_8031fdc4)[(uint)*(byte *)(iVar7 + 0x33b) * 10];
  if (((*(uint *)(iVar7 + 0x2dc) & 0x4000) != 0) ||
     ((dVar10 = (double)*(float *)(iVar7 + 0x328), dVar10 != (double)FLOAT_803e33d8 &&
      (*(short *)(iVar7 + 0x338) != 0)))) goto LAB_80150818;
  bVar1 = *(byte *)(iVar7 + 0x2f1);
  uVar6 = bVar1 & 0x1f;
  if ((bVar1 & 0x10) != 0) {
    uVar6 = bVar1 & 0x17;
  }
  if (0x18 < uVar6) {
    uVar6 = 0;
  }
  fVar2 = FLOAT_803e33e0;
  if ((bVar1 & 0x20) != 0) {
    uVar6 = 0;
    fVar2 = FLOAT_803e33dc;
  }
  dVar11 = (double)fVar2;
  if (((param_11 & 0xff) != 0) &&
     ((((bVar1 != 0 ||
        (dVar10 = (double)*(float *)(iVar7 + 0x324), dVar10 != (double)FLOAT_803e33d8)) &&
       ((*(uint *)(iVar7 + 0x2dc) & 0x40) == 0)) && ((bVar1 & 0x20) == 0)))) {
    param_2 = (double)*(float *)(iVar7 + 0x324);
    dVar10 = (double)FLOAT_803e33d8;
    if (param_2 == dVar10) {
      iVar4 = (uint)*(byte *)(iVar7 + 0x33b) * 2;
      uVar6 = FUN_80017760((uint)(byte)(&DAT_8031feac)[iVar4],(uint)(byte)(&DAT_8031fead)[iVar4]);
      *(float *)(iVar7 + 0x324) =
           *(float *)(iVar7 + 0x334) +
           (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e33f0);
      *(float *)(iVar7 + 0x334) = FLOAT_803e33d8;
      goto LAB_80150818;
    }
    *(float *)(iVar7 + 0x324) = (float)(param_2 - (double)FLOAT_803dc074);
    if (dVar10 < (double)*(float *)(iVar7 + 0x324)) goto LAB_80150818;
    *(float *)(iVar7 + 0x324) = fVar3;
  }
  if ((((((param_11 & 0xff) == 0) || (*(char *)(iVar7 + 0x2f1) == '\0')) ||
       (puVar8[uVar6 * 0xc + 8] == '\0')) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0)) ||
     ((*(byte *)(iVar7 + 0x33c) == uVar6 &&
      (dVar10 = (double)FLOAT_803e33d8, dVar10 != (double)*(float *)(iVar7 + 0x32c))))) {
    if (*(float *)(iVar7 + 0x32c) != FLOAT_803e33d8) {
      dVar10 = (double)*(float *)(*(int *)(iVar7 + 0x29c) + 0x14);
      FUN_8014d3d0(psVar5,iVar7,0xf,0);
      if (FLOAT_803e33e8 < *(float *)(iVar7 + 0x308)) {
        *(float *)(iVar7 + 0x308) = *(float *)(iVar7 + 0x308) - FLOAT_803e33ec;
      }
      if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
        iVar4 = (uint)*(byte *)(iVar7 + 0x33c) * 0xc;
        FUN_8014d4c8((double)*(float *)(puVar8 + iVar4),dVar10,dVar11,param_4,param_5,param_6,
                     param_7,param_8,(int)psVar5,iVar7,(uint)(byte)puVar8[iVar4 + 8],0,
                     *(uint *)(puVar8 + iVar4 + 4) & 0xff,param_14,param_15,param_16);
        FUN_800305c4((double)*(float *)(&DAT_8031e980 +
                                       (uint)(byte)puVar8[(uint)*(byte *)(iVar7 + 0x33c) * 0xc + 8]
                                       * 4),(int)psVar5);
      }
      *(float *)(iVar7 + 0x32c) = *(float *)(iVar7 + 0x32c) - FLOAT_803dc074;
      if (*(float *)(iVar7 + 0x32c) <= FLOAT_803e33d8) {
        *(float *)(iVar7 + 0x32c) = FLOAT_803e33d8;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) & 0xffffffbf;
        *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40000000;
        *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) & 0x7f;
        *(undefined *)(iVar7 + 0x33c) = 0;
      }
    }
  }
  else if (((*(uint *)(iVar7 + 0x2dc) & 0x800080) == 0) && ((*(byte *)(iVar7 + 0x2f1) & 0x20) == 0))
  {
    if ((*(uint *)(iVar7 + 0x2dc) & 0x40000000) != 0) {
      FUN_80151844(dVar10,param_2,dVar11,param_4,param_5,param_6,param_7,param_8,psVar5,iVar7);
    }
  }
  else {
    pfVar9 = (float *)(puVar8 + uVar6 * 0xc);
    fVar3 = FLOAT_803e33e4 * (float)(dVar11 * (double)*pfVar9);
    *(float *)(iVar7 + 0x330) = fVar3;
    *(float *)(iVar7 + 0x32c) = fVar3;
    *(uint *)(iVar7 + 0x2dc) = *(uint *)(iVar7 + 0x2dc) | 0x40;
    *(byte *)(iVar7 + 0x2f2) = *(byte *)(iVar7 + 0x2f2) | 0x80;
    *(undefined *)(iVar7 + 0x2f3) = 0;
    *(undefined *)(iVar7 + 0x2f4) = 0;
    FUN_8014d4c8((double)(float)(dVar11 * (double)*pfVar9),param_2,dVar11,param_4,param_5,param_6,
                 param_7,param_8,(int)psVar5,iVar7,(uint)*(byte *)(pfVar9 + 2),0,
                 (uint)pfVar9[1] & 0xff,param_14,param_15,param_16);
    FUN_800305c4((double)*(float *)(&DAT_8031e980 + (uint)*(byte *)(pfVar9 + 2) * 4),(int)psVar5);
    *(char *)(iVar7 + 0x33c) = (char)uVar6;
  }
LAB_80150818:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: wispbaddie_release
 * EN v1.0 Address: 0x8014FEF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wispbaddie_release(void)
{
}

/*
 * --INFO--
 *
 * Function: wispbaddie_initialise
 * EN v1.0 Address: 0x8014FEF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wispbaddie_initialise(void)
{
}
