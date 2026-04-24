#include "ghidra_import.h"
#include "main/dll/seqObj11E.h"

extern bool FUN_8000b5f0();
extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e054();
extern int FUN_80010340();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_80036548();
extern undefined4 FUN_80037da8();
extern undefined4 FUN_80037e24();
extern int FUN_800395a4();
extern undefined4 FUN_8009742c();
extern undefined4 FUN_80098608();
extern undefined4 FUN_8011f670();
extern undefined4 FUN_8011f6d0();
extern undefined4 FUN_8014d3f4();
extern undefined4 FUN_8014d504();
extern byte FUN_801a06f0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern int FUN_80296ffc();
extern undefined4 FUN_8029700c();

extern undefined4 DAT_8031fee0;
extern undefined4 DAT_8031fee4;
extern undefined4 DAT_8031fee8;
extern undefined4 DAT_8031fee9;
extern undefined4 DAT_8031feea;
extern undefined4 DAT_8031feeb;
extern undefined4 DAT_803dc908;
extern undefined4 DAT_803dc910;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e34b0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dc918;
extern f32 FLOAT_803dc91c;
extern f32 FLOAT_803e3470;
extern f32 FLOAT_803e3474;
extern f32 FLOAT_803e3480;
extern f32 FLOAT_803e3490;
extern f32 FLOAT_803e3494;
extern f32 FLOAT_803e3498;
extern f32 FLOAT_803e349c;
extern f32 FLOAT_803e34a0;
extern f32 FLOAT_803e34a4;
extern f32 FLOAT_803e34a8;
extern f32 FLOAT_803e34ac;
extern f32 FLOAT_803e34b8;
extern f32 FLOAT_803e34bc;
extern f32 FLOAT_803e34c0;
extern f32 FLOAT_803e34c4;
extern f32 FLOAT_803e34c8;
extern f32 FLOAT_803e34cc;
extern f32 FLOAT_803e34d0;
extern f32 FLOAT_803e34d4;
extern f32 FLOAT_803e34d8;
extern f32 FLOAT_803e34dc;
extern f32 FLOAT_803e34e0;
extern f32 FLOAT_803e34e4;
extern undefined2 uRam803dc90a;
extern undefined4 uRam803dc90c;

/*
 * --INFO--
 *
 * Function: FUN_801520fc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801520FC
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801520fc(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8002bac4();
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x1be);
  if (iVar2 == 0) {
    FUN_8011f670(2);
    *(undefined2 *)(param_2 + 0x338) = DAT_803dc908;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  else if ((iVar1 == 0) || (iVar2 = FUN_80296ffc(iVar1), iVar2 < 0x19)) {
    FUN_8011f670(2);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90a;
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
  }
  else {
    FUN_8029700c(iVar1,-0x19);
    FUN_800201ac((int)*(short *)(iVar3 + 0x1c),1);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90c;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8011f670(2);
    (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015224c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8015224C
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015224c(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  iVar3 = FUN_8002bac4();
  iVar4 = *(int *)(param_1 + 0x4c);
  fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(param_1 + 0x10);
  if (fVar1 < FLOAT_803e3470) {
    fVar1 = -fVar1;
  }
  if (fVar1 <= FLOAT_803e3474) {
    dVar5 = (double)FUN_802945e0();
    dVar8 = -(double)(float)((double)FLOAT_803e3474 * dVar5 - (double)*(float *)(iVar4 + 8));
    dVar5 = (double)FUN_80294964();
    dVar7 = -(double)(float)((double)FLOAT_803e3474 * dVar5 - (double)*(float *)(iVar4 + 0x10));
    fVar1 = (float)((double)*(float *)(iVar3 + 0x18) - dVar8);
    fVar2 = (float)((double)*(float *)(iVar3 + 0x20) - dVar7);
    dVar5 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar5 < (double)*(float *)(param_2 + 0x2ac)) {
      dVar5 = (double)FUN_802945e0();
      dVar6 = (double)FUN_80294964();
      fVar1 = -(float)(dVar5 * (double)(float)(dVar8 - dVar5) +
                      (double)(float)(dVar6 * (double)(float)(dVar7 - dVar6)));
      dVar7 = (double)(fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x8c) +
                                      (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x94))));
      if ((FLOAT_803e3470 <
           fVar1 + (float)(dVar5 * (double)*(float *)(iVar3 + 0x18) +
                          (double)(float)(dVar6 * (double)*(float *)(iVar3 + 0x20)))) &&
         ((double)FLOAT_803e3480 <= dVar7)) {
        *(float *)(iVar3 + 0x18) = -(float)(dVar5 * dVar7 - (double)*(float *)(iVar3 + 0x18));
        *(float *)(iVar3 + 0x20) = -(float)(dVar6 * dVar7 - (double)*(float *)(iVar3 + 0x20));
        FUN_8000e054((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                     (double)*(float *)(iVar3 + 0x20),(float *)(iVar3 + 0xc),(float *)(iVar3 + 0x10)
                     ,(float *)(iVar3 + 0x14),*(int *)(iVar3 + 0x30));
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152498
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80152498
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152498(uint param_1,int param_2)
{
  FUN_8000bb38(param_1,0x23);
  *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801524d4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801524D4
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801524d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  ushort uVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(char *)(param_10 + 0x33a) == '\x02') &&
     (uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c)), uVar2 == 0)) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
      FUN_8011f6d0(7);
    }
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_801520fc(param_9,param_10);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if (((*(uint *)(param_10 + 0x2dc) & 0x80000000) != 0) &&
     (*(int *)(&DAT_8031fee4 + (uint)*(byte *)(param_10 + 0x33a) * 0xc) != 0)) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    uVar2 = (uint)*(byte *)(param_10 + 0x33a);
    if (uVar2 == 0) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x20000000) != 0) {
        uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
        if (uVar2 == 0) {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
        else {
          *(undefined *)(param_10 + 0x33a) =
               (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
        }
      }
    }
    else if (uVar2 == 2) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
      if ((uVar2 != 0) || ((*(uint *)(param_10 + 0x2dc) & 0x20000000) == 0)) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else if (uVar2 == 3) {
      uVar2 = FUN_80020078((int)*(short *)(iVar3 + 0x1c));
      if (uVar2 == 0) {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
      else {
        *(undefined *)(param_10 + 0x33a) = (&DAT_8031feea)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
      }
    }
    else {
      *(undefined *)(param_10 + 0x33a) = (&DAT_8031fee9)[uVar2 * 0xc];
    }
    uVar1 = (ushort)(byte)(&DAT_8031fee8)[(uint)*(byte *)(param_10 + 0x33a) * 0xc];
    if (*(ushort *)(param_9 + 0xa0) != uVar1) {
      if ((uVar1 != 0) && (uVar1 != 4)) {
        FUN_8000bb38(param_9,0x4a8);
      }
      iVar3 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
      FUN_8014d504((double)*(float *)(&DAT_8031fee0 + iVar3),param_2,param_3,param_4,param_5,param_6
                   ,param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_8031fee8)[iVar3],0,0xf,in_r8,
                   in_r9,in_r10);
    }
  }
  if ((&DAT_8031feeb)[(uint)*(byte *)(param_10 + 0x33a) * 0xc] != '\0') {
    FUN_8015224c(param_9,param_10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015278c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8015278C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015278c(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3490;
  *(float *)(param_2 + 0x2a8) = FLOAT_803e3494;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0xc80;
  *(float *)(param_2 + 0x308) = FLOAT_803e3498;
  *(float *)(param_2 + 0x300) = FLOAT_803e349c;
  *(float *)(param_2 + 0x304) = FLOAT_803e34a0;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e34a4;
  *(float *)(param_2 + 0x314) = FLOAT_803e34a4;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  if (*(char *)(iVar2 + 0x2e) != -1) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 1;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015281c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8015281C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8015281c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined2 param_10
            )
{
  uint uVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  FUN_8002bac4();
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) == 0) {
    uVar2 = 0;
  }
  else {
    puVar3 = FUN_8002becc(0x24,param_10);
    *puVar3 = param_10;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar4 + 7);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)((int)puVar3 + 0x19) = 0;
    puVar3[0x10] = 0x95;
    uVar2 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801528ec
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801528EC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801528ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x4c);
  if ((param_12 != 0x10) && (param_12 != 0x11)) {
    FUN_8000bb38(param_9,0x23);
    FUN_8000bb38(param_9,0x31b);
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
    *(float *)(param_10 + 0x32c) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x2c)) - DOUBLE_803e34b0);
    FUN_8014d504((double)FLOAT_803e34a8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,param_14,param_15,param_16);
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xffffffdf;
    fVar1 = FLOAT_803e34ac;
    *(float *)(param_9 + 0x2c) = FLOAT_803e34ac;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801529c0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801529C0
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801529c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short *psVar1;
  int iVar2;
  char cVar7;
  short sVar5;
  short sVar6;
  bool bVar8;
  byte bVar9;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar10;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  undefined auStack_48 [8];
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  uVar14 = FUN_80286840();
  psVar1 = (short *)((ulonglong)uVar14 >> 0x20);
  puVar10 = (undefined4 *)uVar14;
  iVar12 = *(int *)(psVar1 + 0x26);
  pfVar11 = (float *)*puVar10;
  if ((double)FLOAT_803e34ac < (double)(float)puVar10[0xcb]) {
    if (*(int *)(psVar1 + 100) != 0) {
      FUN_8002cc9c((double)(float)puVar10[0xcb],param_2,param_3,param_4,param_5,param_6,param_7,
                   param_8,*(int *)(psVar1 + 100));
      FUN_80037da8((int)psVar1,*(int *)(psVar1 + 100));
      psVar1[100] = 0;
      psVar1[0x65] = 0;
    }
    puVar10[0xcb] = (float)puVar10[0xcb] - FLOAT_803dc074;
    if (FLOAT_803e34ac < (float)puVar10[0xcb]) {
      if ((puVar10[0xb9] & 0x20) == 0) goto LAB_80152f28;
    }
    else {
      puVar10[0xcb] = FLOAT_803e34ac;
      puVar10[0xb9] = puVar10[0xb9] | 0x20;
      FUN_8000b7dc((int)psVar1,4);
      FUN_8014d504((double)FLOAT_803e34b8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)psVar1,(int)puVar10,0,0,0,in_r8,in_r9,in_r10);
    }
  }
  if ((puVar10[0xb7] & 0x2000) == 0) {
    if (FLOAT_803e34c8 <= *(float *)(psVar1 + 8) - *(float *)(iVar12 + 0xc)) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_8000b5f0((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_8000bb38((uint)psVar1,0x18d);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
    *psVar1 = *psVar1 + (short)*(char *)(iVar12 + 0x2a);
  }
  else {
    iVar2 = FUN_80010340((double)(float)puVar10[0xbf],pfVar11);
    if ((((iVar2 != 0) || (pfVar11[4] != 0.0)) &&
        (cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar11), cVar7 != '\0')) &&
       (cVar7 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e34bc,*puVar10,psVar1,&DAT_803dc910,0xffffffff),
       cVar7 != '\0')) {
      puVar10[0xb7] = puVar10[0xb7] & 0xffffdfff;
    }
    *(float *)(psVar1 + 0x12) = (pfVar11[0x1a] - *(float *)(psVar1 + 6)) / FLOAT_803dc074;
    *(float *)(psVar1 + 0x16) = (pfVar11[0x1c] - *(float *)(psVar1 + 10)) / FLOAT_803dc074;
    iVar2 = (int)*(char *)(iVar12 + 0x2a);
    if (iVar2 == 0) {
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3f4(psVar1,puVar10,0xf,0);
    }
    else if ((puVar10[0xb7] & 0x2000) == 0) {
      local_28 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        iVar2 = -iVar2;
      }
      *psVar1 = *psVar1 + (short)iVar2;
    }
    else {
      sVar6 = (short)(iVar2 << 8);
      local_30 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      sVar5 = sVar6;
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        sVar5 = -sVar6;
      }
      *psVar1 = *psVar1 - sVar5;
      param_2 = (double)pfVar11[0x1c];
      FUN_8014d3f4(psVar1,puVar10,0xf,0);
      local_28 = (longlong)(int)(FLOAT_803e34c0 * pfVar11[0x1e]);
      if ((int)(FLOAT_803e34c0 * pfVar11[0x1e]) < 0) {
        sVar6 = -sVar6;
      }
      *psVar1 = *psVar1 + sVar6;
    }
    if (FLOAT_803e34c4 <= *(float *)(psVar1 + 8) - pfVar11[0x1b]) {
      *(undefined *)((int)puVar10 + 0x33a) = 0;
    }
    else {
      bVar8 = FUN_8000b5f0((int)psVar1,0x18d);
      if (!bVar8) {
        FUN_8000bb38((uint)psVar1,0x18d);
      }
      *(undefined *)((int)puVar10 + 0x33a) = 1;
    }
  }
  if (*(char *)((int)puVar10 + 0x33a) != '\0') {
    param_2 = (double)FLOAT_803dc918;
    *(float *)(psVar1 + 0x14) =
         (float)(param_2 * (double)FLOAT_803dc074 + (double)*(float *)(psVar1 + 0x14));
  }
  if ((psVar1[0x58] & 0x800U) != 0) {
    local_3c = FLOAT_803e34ac;
    local_38 = FLOAT_803e34ac;
    local_34 = FLOAT_803e34ac;
    local_40 = FLOAT_803e34b8;
    param_2 = (double)FLOAT_803e34d0;
    FUN_80098608((double)FLOAT_803e34cc,param_2);
    local_38 = FLOAT_803e34d4;
    FUN_8009742c((double)FLOAT_803e34d8,psVar1,1,6,0x20,(int)auStack_48);
    local_3c = FLOAT_803e34ac;
    local_38 = FLOAT_803e34dc;
    local_34 = FLOAT_803e34dc;
  }
  if (FLOAT_803e34e0 <= *(float *)(psVar1 + 0x14)) {
    if (FLOAT_803e34cc < *(float *)(psVar1 + 0x14)) {
      *(float *)(psVar1 + 0x14) = FLOAT_803e34cc;
    }
  }
  else {
    *(float *)(psVar1 + 0x14) = FLOAT_803e34e0;
  }
  dVar13 = (double)FLOAT_803e34ac;
  if (dVar13 == (double)(float)puVar10[0xcb]) {
    if (((*(char *)(iVar12 + 0x2e) != -1) && (*(int *)(psVar1 + 100) != 0)) &&
       (bVar9 = FUN_801a06f0(*(int *)(psVar1 + 100)), bVar9 != 0)) {
      iVar2 = FUN_8002bac4();
      FUN_80036548(iVar2,(int)psVar1,'\x16',2,0);
      FUN_8015281c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)psVar1,0x3b2)
      ;
      FUN_8000bb38((uint)psVar1,0xe9);
      puVar10[0xcb] = FLOAT_803dc91c;
    }
    dVar13 = (double)FLOAT_803e34e4;
    local_28 = (longlong)(int)(dVar13 * (double)FLOAT_803dc078);
    uVar3 = FUN_80022264(0,(int)(dVar13 * (double)FLOAT_803dc078));
    if (uVar3 == 0) {
      dVar13 = (double)FUN_8000bb38((uint)psVar1,0xe7);
    }
    if (*(int *)(psVar1 + 100) == 0) {
      cVar7 = *(char *)(iVar12 + 0x2a);
      iVar2 = FUN_8015281c(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)psVar1,0x639);
      uVar4 = 0;
      if ((*(char *)(iVar12 + 0x2a) != '\0') && ((puVar10[0xb7] & 0x2000) == 0)) {
        uVar4 = 1;
      }
      *(undefined4 *)(iVar2 + 0xf4) = uVar4;
      FUN_80037e24((int)psVar1,iVar2,(ushort)(cVar7 != '\0'));
    }
    else {
      iVar12 = FUN_800395a4(*(int *)(psVar1 + 100),0);
      if (iVar12 != 0) {
        iVar2 = *(short *)(iVar12 + 8) + -0x3c;
        if (iVar2 < 0) {
          iVar2 = *(short *)(iVar12 + 8) + 0x26d4;
        }
        *(short *)(iVar12 + 8) = (short)iVar2;
      }
    }
  }
LAB_80152f28:
  FUN_8028688c();
  return;
}
