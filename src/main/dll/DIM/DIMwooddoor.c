#include "ghidra_import.h"
#include "main/dll/DIM/DIMwooddoor.h"

extern undefined4 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80021884();
extern uint FUN_80022264();
extern undefined4 FUN_8002ba34();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035a6c();
extern undefined4 FUN_80035eec();
extern int FUN_800396d0();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_8009adfc();
extern ulonglong FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb6a;
extern undefined4 DAT_803dcb6c;
extern f64 DOUBLE_803e5558;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dcb58;
extern f32 FLOAT_803dcb7c;
extern f32 FLOAT_803e5538;
extern f32 FLOAT_803e553c;
extern f32 FLOAT_803e5540;
extern f32 FLOAT_803e5544;
extern f32 FLOAT_803e5548;
extern f32 FLOAT_803e5550;
extern f32 FLOAT_803e5560;
extern f32 FLOAT_803e5564;
extern f32 FLOAT_803e5568;
extern f32 FLOAT_803e556c;
extern f32 FLOAT_803e5570;

/*
 * --INFO--
 *
 * Function: FUN_801b206c
 * EN v1.0 Address: 0x801B1FF4
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x801B206C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b206c(undefined2 *param_1,int param_2)
{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *puVar2 = (char)*(undefined2 *)(param_2 + 0x1a);
  if ((int)*(short *)(param_2 + 0x1e) != 0xffffffff) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
    puVar2[1] = (char)uVar1;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2108
 * EN v1.0 Address: 0x801B2070
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B2108
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2108(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b213c
 * EN v1.0 Address: 0x801B2098
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x801B213C
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b213c(uint param_1)
{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  psVar6 = *(short **)(param_1 + 0xb8);
  if (*(char *)(psVar6 + 1) == '\x01') {
    iVar3 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -0x10;
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(char *)(param_1 + 0x36) = (char)iVar3;
    *psVar6 = *psVar6 - (ushort)DAT_803dc070;
    if (*psVar6 < 1) {
      FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
      *(undefined *)(psVar6 + 1) = 2;
    }
  }
  else if (*(char *)(psVar6 + 1) == '\0') {
    bVar1 = false;
    iVar3 = 0;
    iVar4 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
    if (0 < iVar4) {
      do {
        iVar5 = *(int *)(*(int *)(param_1 + 0x58) + iVar3 + 0x100);
        if ((*(short *)(iVar5 + 0x46) == 0x1d6) && (*(char *)(*(int *)(iVar5 + 0xb8) + 4) != '\0'))
        {
          bVar1 = true;
          break;
        }
        iVar3 = iVar3 + 4;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    if (bVar1) {
      cVar2 = *(char *)((int)psVar6 + 3) + -1;
      *(char *)((int)psVar6 + 3) = cVar2;
      if (cVar2 < '\x01') {
        *(undefined *)(psVar6 + 1) = 1;
        *psVar6 = 0x1e;
        FUN_8000bb38(param_1,0x206);
      }
      else {
        FUN_8000bb38(param_1,0x207);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2290
 * EN v1.0 Address: 0x801B21CC
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801B2290
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2290(undefined2 *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined *)(iVar2 + 3) = 1;
  *(undefined *)(iVar2 + 2) = 0;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    *(undefined *)(iVar2 + 3) = 0;
    *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    *(undefined *)(param_1 + 0x1b) = 0;
    *(undefined *)(iVar2 + 2) = 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2338
 * EN v1.0 Address: 0x801B2260
 * EN v1.0 Size: 992b
 * EN v1.1 Address: 0x801B2338
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2338(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)
{
  uint uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_9 + 0x5c);
  if ((*(char *)(piVar3 + 2) != '\x01') && (*(char *)(piVar3 + 2) == '\0')) {
    param_4 = (double)*(float *)(param_9 + 0x14);
    *(float *)(param_9 + 0x14) =
         (float)((double)(FLOAT_803e553c * -FLOAT_803dcb58) * (double)FLOAT_803dc074 + param_4);
    param_1 = (double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074);
    param_2 = (double)(FLOAT_803e5540 * (float)(param_4 + (double)*(float *)(param_9 + 0x14)) *
                      FLOAT_803dc074);
    param_3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    FUN_8002ba34(param_1,param_2,param_3,(int)param_9);
    param_9[2] = param_9[2] + *(char *)((int)piVar3 + 9) * 10;
    param_9[1] = param_9[1] + *(char *)((int)piVar3 + 10) * 10;
    *param_9 = *param_9 + *(char *)((int)piVar3 + 0xb) * 10;
    iVar2 = *(int *)(param_9 + 0x2a);
    if (iVar2 != 0) {
      param_1 = (double)FUN_80035eec((int)param_9,5,*(undefined *)((int)piVar3 + 6),0);
      iVar2 = *(int *)(iVar2 + 0x50);
      if ((iVar2 != 0) && (iVar2 != *piVar3)) {
        FUN_80035a6c((int)param_9,(ushort)*(byte *)((int)piVar3 + 5));
        param_1 = (double)FUN_8009adfc((double)FLOAT_803e5538,param_2,param_3,param_4,param_5,
                                       param_6,param_7,param_8,param_9,2,1,0,1,1,1,0);
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x49c;
        *(undefined *)(piVar3 + 2) = 1;
        param_9[3] = param_9[3] | 0x4000;
      }
    }
    uVar1 = FUN_80020078(0x85e);
    if (((uVar1 != 0) && (uVar1 = FUN_80020078(0xc2d), uVar1 == 0)) ||
       ((uVar1 = FUN_80020078(0x874), uVar1 != 0 && (uVar1 = FUN_80020078(0xc2e), uVar1 == 0)))) {
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x4b0;
    }
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
      FUN_80035a6c((int)param_9,(ushort)*(byte *)((int)piVar3 + 5));
      param_1 = (double)FUN_8009adfc((double)FLOAT_803e5538,param_2,param_3,param_4,param_5,param_6,
                                     param_7,param_8,param_9,2,1,0,1,1,1,0);
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x49c;
      *(undefined *)(piVar3 + 2) = 1;
      param_9[3] = param_9[3] | 0x4000;
    }
  }
  *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + (uint)DAT_803dc070;
  if (*(int *)(param_9 + 0x7a) < 0x4b1) {
    if (*(char *)((int)piVar3 + 7) != '\0') {
      *(undefined *)((int)piVar3 + 7) = 0;
    }
  }
  else {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b25a8
 * EN v1.0 Address: 0x801B2640
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B25A8
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b25a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801b27f8
 * EN v1.0 Address: 0x801B2644
 * EN v1.0 Size: 780b
 * EN v1.1 Address: 0x801B27F8
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b27f8(void)
{
  char cVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  short sVar6;
  int iVar5;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  
  iVar7 = FUN_8028683c();
  iVar12 = *(int *)(iVar7 + 0x4c);
  iVar8 = FUN_8002bac4();
  iVar13 = *(int *)(iVar7 + 0xb8);
  if (*(short *)(iVar13 + 0xa6) < 1) {
    iVar7 = FUN_800396d0(iVar7,0);
    sVar2 = *(short *)(iVar7 + 2);
    cVar1 = *(char *)(iVar12 + 0x28);
    uVar9 = FUN_80021884();
    iVar10 = ((uVar9 & 0xffff) + 0x8000) - ((int)sVar2 + cVar1 * 0x100 & 0xffffU);
    if (0x8000 < iVar10) {
      iVar10 = iVar10 + -0xffff;
    }
    if (iVar10 < -0x8000) {
      iVar10 = iVar10 + 0xffff;
    }
    if ((iVar10 < 0x1200) && (-0x1200 < iVar10)) {
      *(undefined *)(iVar13 + 0xad) = 1;
    }
    if (0x800 < iVar10) {
      iVar10 = 0x800;
    }
    if (iVar10 < -0x800) {
      iVar10 = -0x800;
    }
    iVar10 = iVar10 >> 3;
    if (iVar10 != 0) {
      sVar2 = *(short *)(iVar7 + 2);
      sVar6 = sVar2;
      if (sVar2 < 0) {
        sVar6 = -sVar2;
      }
      if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar6) {
        if (iVar10 < 0) {
          iVar11 = -1;
        }
        else if (iVar10 < 1) {
          iVar11 = 0;
        }
        else {
          iVar11 = 1;
        }
        if (sVar2 < 0) {
          iVar5 = -1;
        }
        else if (sVar2 < 1) {
          iVar5 = 0;
        }
        else {
          iVar5 = 1;
        }
        if (iVar5 == iVar11) {
          iVar10 = (iVar10 * ((int)DAT_803dcb6a - (int)sVar6)) / (int)DAT_803dcb6c;
        }
      }
      *(short *)(iVar7 + 2) = *(short *)(iVar7 + 2) + (short)iVar10;
    }
    fVar3 = *(float *)(iVar13 + 0x8c) - *(float *)(iVar13 + 4);
    fVar4 = *(float *)(iVar13 + 0x94) - *(float *)(iVar13 + 0xc);
    dVar16 = (double)(fVar3 * fVar3 + fVar4 * fVar4);
    dVar14 = FUN_80293900(dVar16);
    dVar15 = (double)FLOAT_803e5560;
    fVar3 = (float)(dVar15 + (double)*(float *)(iVar13 + 8)) - *(float *)(iVar13 + 0x90);
    if (dVar15 < dVar16) {
      dVar15 = dVar16;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    if (((dVar15 < (double)(float)((double)CONCAT44(0x43300000,iVar7 * iVar7 ^ 0x80000000) -
                                  DOUBLE_803e5558)) || (fVar3 < FLOAT_803dcb7c)) ||
       ((*(ushort *)(iVar8 + 0xb0) & 0x1000) != 0)) {
      *(undefined *)(iVar13 + 0xad) = 0;
    }
    iVar7 = (uint)*(byte *)(iVar12 + 0x2b) * 2;
    uVar9 = iVar7 * iVar7 ^ 0x80000000;
    if (dVar15 <= (double)(float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e5558)) {
      dVar15 = (double)(float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e5558);
    }
    fVar3 = FLOAT_803e5564 * fVar3 - (float)((double)FLOAT_803e5568 * dVar14);
    fVar4 = FLOAT_803e556c;
    if (fVar3 < FLOAT_803e556c) {
      fVar4 = fVar3;
    }
    dVar14 = (double)((float)((double)(FLOAT_803e553c * -FLOAT_803dcb58) * dVar15) / fVar4);
    dVar15 = (double)FLOAT_803e5550;
    if (dVar15 < dVar14) {
      dVar15 = dVar14;
    }
    dVar15 = FUN_80293900(dVar15);
    *(float *)(iVar13 + 0x98) =
         (float)((double)*(float *)(iVar13 + 0x98) +
                (double)((float)(dVar15 - (double)*(float *)(iVar13 + 0x98)) / FLOAT_803e5570));
  }
  FUN_80286888();
  return;
}
