#include "ghidra_import.h"
#include "main/objanim.h"

extern undefined4 FUN_80024f40();
extern undefined4 FUN_8007d858();

extern f64 DOUBLE_803df568;
extern f64 DOUBLE_803df580;
extern f32 FLOAT_803df560;
extern f32 FLOAT_803df570;
extern f32 FLOAT_803df574;
extern f32 FLOAT_803df578;
extern f32 FLOAT_803df588;

/*
 * --INFO--
 *
 * Function: FUN_8002ec4c
 * EN v1.0 Address: 0x8002EC4C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8002ec4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10,int param_11,uint param_12,undefined2 param_13)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = (int)*(short *)(param_10 + ((int)param_12 >> 8) * 2 + 0x70) + (param_12 & 0xff);
  if ((int)(uint)*(ushort *)(param_10 + 0xec) <= iVar3) {
    iVar3 = *(ushort *)(param_10 + 0xec) - 1;
  }
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  if ((*(ushort *)(param_10 + 2) & 0x40) == 0) {
    *(short *)(param_11 + 0x48) = (short)iVar3;
    iVar3 = *(int *)(*(int *)(param_10 + 100) + (uint)*(ushort *)(param_11 + 0x48) * 4);
  }
  else {
    if (*(short *)(param_11 + 100) != iVar3) {
      *(short *)(param_11 + 0x48) = (short)*(char *)(param_11 + 0x62);
      *(short *)(param_11 + 0x4a) = 1 - *(char *)(param_11 + 0x62);
      if (*(short *)(*(int *)(param_10 + 0x6c) + iVar3 * 2) == -1) {
        param_1 = FUN_8007d858();
        iVar3 = 0;
      }
      FUN_80024f40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)*(short *)(*(int *)(param_10 + 0x6c) + iVar3 * 2),(int)(short)iVar3,
                   *(undefined4 *)(param_11 + (uint)*(ushort *)(param_11 + 0x48) * 4 + 0x24),
                   param_10);
      *(short *)(param_11 + 100) = (short)iVar3;
    }
    iVar3 = *(int *)(param_11 + (uint)*(ushort *)(param_11 + 0x48) * 4 + 0x24) + 0x80;
  }
  *(int *)(param_11 + 0x3c) = iVar3 + 6;
  uVar2 = (int)*(char *)(iVar3 + 1) & 0xf0;
  if (uVar2 == (int)*(char *)(param_11 + 0x60)) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_11 + 0x3c) + 1)) -
                   DOUBLE_803df568);
    if (uVar2 == 0) {
      fVar1 = fVar1 - FLOAT_803df560;
    }
    if (fVar1 == *(float *)(param_11 + 0x14)) {
      *(undefined2 *)(param_11 + 0x5a) = param_13;
    }
    else {
      *(undefined2 *)(param_11 + 0x5a) = 0;
    }
  }
  else {
    *(undefined2 *)(param_11 + 0x5a) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8002ee10
 * EN v1.0 Address: 0x8002EE10
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8002ee10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined2 param_11)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  iVar1 = *piVar2;
  if (*(short *)(iVar1 + 0xec) != 0) {
    FUN_8002ec4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar1,
                 piVar2[0xc],param_10,param_11);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8002ee64
 * EN v1.0 Address: 0x8002EE64
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8002ee64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined2 param_11)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  iVar1 = *piVar2;
  if (*(short *)(iVar1 + 0xec) != 0) {
    FUN_8002ec4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar1,
                 piVar2[0xb],param_10,param_11);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8002eeb8
 * EN v1.0 Address: 0x8002EEB8
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8002eeb8(double param_1,double param_2,int param_3,int param_4)
{
  int iVar1;
  int iVar2;
  char cVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  uint uVar14;
  undefined uVar15;
  undefined8 local_28;
  
  uVar7 = 0;
  piVar10 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (*(short *)(*piVar10 + 0xec) == 0) {
    uVar7 = 0;
  }
  else {
    iVar11 = piVar10[0xc];
    *(float *)(iVar11 + 0xc) = (float)(param_1 * (double)*(float *)(iVar11 + 0x14));
    if (*(short *)(iVar11 + 0x58) != 0) {
      if ((*(byte *)(iVar11 + 99) & 8) != 0) {
        *(undefined4 *)(iVar11 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
      }
      *(float *)(iVar11 + 8) =
           (float)((double)*(float *)(iVar11 + 0x10) * param_2 + (double)*(float *)(iVar11 + 8));
      fVar5 = FLOAT_803df570;
      fVar4 = *(float *)(iVar11 + 0x18);
      if (*(char *)(iVar11 + 0x61) == '\0') {
        fVar5 = *(float *)(iVar11 + 8);
        fVar6 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        *(float *)(iVar11 + 8) = fVar6;
      }
      else {
        if (*(float *)(iVar11 + 8) < FLOAT_803df570) {
          while (*(float *)(iVar11 + 8) < fVar5) {
            *(float *)(iVar11 + 8) = *(float *)(iVar11 + 8) + fVar4;
          }
        }
        if (fVar4 <= *(float *)(iVar11 + 8)) {
          while (fVar4 <= *(float *)(iVar11 + 8)) {
            *(float *)(iVar11 + 8) = *(float *)(iVar11 + 8) - fVar4;
          }
        }
      }
      if ((*(byte *)(iVar11 + 99) & 2) == 0) {
        uVar8 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (uint)*(ushort *)(iVar11 + 0x5e)) -
                                              DOUBLE_803df568) * param_2 -
                              (double)(float)((double)CONCAT44(0x43300000,
                                                               *(ushort *)(iVar11 + 0x58) ^
                                                               0x80000000) - DOUBLE_803df580));
        fVar4 = FLOAT_803df570;
        if ((-1 < (int)uVar8) &&
           (uVar8 = uVar8 ^ 0x80000000, fVar4 = FLOAT_803df574,
           (float)((double)CONCAT44(0x43300000,uVar8) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_28 = (double)CONCAT44(0x43300000,uVar8);
          fVar4 = (float)(local_28 - DOUBLE_803df580);
        }
        *(short *)(iVar11 + 0x58) = (short)(int)fVar4;
      }
      if (*(short *)(iVar11 + 0x58) == 0) {
        *(undefined2 *)(iVar11 + 0x5c) = 0;
      }
    }
    fVar4 = *(float *)(param_3 + 0x9c);
    *(float *)(param_3 + 0x9c) = fVar4 + (float)(param_1 * param_2);
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (*(float *)(param_3 + 0x9c) < FLOAT_803df560) {
      if (*(float *)(param_3 + 0x9c) < FLOAT_803df570) {
        if (*(char *)(iVar11 + 0x60) == '\0') {
          *(float *)(param_3 + 0x9c) = FLOAT_803df570;
        }
        else {
          while (*(float *)(param_3 + 0x9c) < fVar6) {
            *(float *)(param_3 + 0x9c) = *(float *)(param_3 + 0x9c) + fVar5;
          }
        }
        uVar7 = 1;
      }
    }
    else {
      if (*(char *)(iVar11 + 0x60) == '\0') {
        *(float *)(param_3 + 0x9c) = FLOAT_803df560;
      }
      else {
        while (fVar5 <= *(float *)(param_3 + 0x9c)) {
          *(float *)(param_3 + 0x9c) = *(float *)(param_3 + 0x9c) - fVar5;
        }
      }
      uVar7 = 1;
    }
    if ((param_4 != 0) && (*(undefined *)(param_4 + 0x12) = 0, *(int *)(param_3 + 0x60) != 0)) {
      *(undefined *)(param_4 + 0x1b) = 0;
      iVar11 = **(int **)(param_3 + 0x60) >> 1;
      if (iVar11 != 0) {
        iVar1 = (int)(FLOAT_803df578 * fVar4);
        iVar2 = (int)(FLOAT_803df578 * *(float *)(param_3 + 0x9c));
        bVar13 = iVar2 < iVar1;
        if ((float)(param_1 * param_2) < FLOAT_803df570) {
          bVar13 = bVar13 | 2;
        }
        iVar12 = 0;
        iVar9 = 0;
        while ((iVar12 < iVar11 && (*(char *)(param_4 + 0x1b) < '\b'))) {
          uVar14 = (uint)*(short *)(*(int *)(*(int *)(param_3 + 0x60) + 4) + iVar9);
          uVar8 = uVar14 & 0x1ff;
          uVar14 = uVar14 >> 9 & 0x7f;
          if (uVar14 != 0x7f) {
            uVar15 = (undefined)uVar14;
            if (((bVar13 == 0) && (iVar1 <= (int)uVar8)) && ((int)uVar8 < iVar2)) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if ((bVar13 == 1) && ((iVar1 <= (int)uVar8 || ((int)uVar8 < iVar2)))) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if (((bVar13 == 3) && (iVar2 < (int)uVar8)) && ((int)uVar8 <= iVar1)) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if ((bVar13 == 2) && ((iVar2 < (int)uVar8 || ((int)uVar8 <= iVar1)))) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
          }
          iVar9 = iVar9 + 2;
          iVar12 = iVar12 + 1;
        }
      }
    }
  }
  return uVar7;
}

/*
 * --INFO--
 *
 * Function: FUN_8002f304
 * EN v1.0 Address: 0x8002F304
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8002f304(double param_1,int param_2)
{
  double dVar1;
  
  dVar1 = (double)FLOAT_803df588;
  if ((param_1 <= dVar1) && (dVar1 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar1 = (double)FLOAT_803df570;
  }
  *(float *)(param_2 + 0x9c) = (float)dVar1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8002f334
 * EN v1.0 Address: 0x8002F334
 * EN v1.0 Size: 720b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8002f334(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint param_10,
            undefined param_11)
{
  short sVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  dVar7 = (double)FLOAT_803df560;
  if ((param_1 <= dVar7) && (dVar7 = param_1, param_1 < (double)FLOAT_803df570)) {
    dVar7 = (double)FLOAT_803df570;
  }
  *(float *)(param_9 + 0x9c) = (float)dVar7;
  piVar4 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  iVar6 = *piVar4;
  if (*(short *)(iVar6 + 0xec) != 0) {
    iVar5 = piVar4[0xc];
    *(undefined *)(iVar5 + 99) = param_11;
    *(undefined2 *)(iVar5 + 0x46) = *(undefined2 *)(iVar5 + 0x44);
    *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar5 + 4);
    *(undefined4 *)(iVar5 + 0x18) = *(undefined4 *)(iVar5 + 0x14);
    *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(iVar5 + 0x38) = *(undefined4 *)(iVar5 + 0x34);
    *(undefined *)(iVar5 + 0x61) = *(undefined *)(iVar5 + 0x60);
    *(undefined2 *)(iVar5 + 0x4a) = *(undefined2 *)(iVar5 + 0x48);
    *(undefined4 *)(iVar5 + 0x40) = *(undefined4 *)(iVar5 + 0x3c);
    *(undefined2 *)(iVar5 + 0x5c) = *(undefined2 *)(iVar5 + 0x5a);
    *(undefined2 *)(iVar5 + 0x5a) = 0;
    *(undefined2 *)(iVar5 + 100) = 0xffff;
    sVar1 = *(short *)(param_9 + 0xa2);
    *(short *)(param_9 + 0xa2) = (short)param_10;
    iVar3 = (int)*(short *)(iVar6 + ((int)param_10 >> 8) * 2 + 0x70) + (param_10 & 0xff);
    if ((int)(uint)*(ushort *)(iVar6 + 0xec) <= iVar3) {
      iVar3 = *(ushort *)(iVar6 + 0xec) - 1;
    }
    if (iVar3 < 0) {
      iVar3 = 0;
    }
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      *(short *)(iVar5 + 0x44) = (short)iVar3;
      iVar6 = *(int *)(*(int *)(iVar6 + 100) + (uint)*(ushort *)(iVar5 + 0x44) * 4);
    }
    else {
      if ((int)(param_10 - (int)sVar1 | (int)sVar1 - param_10) < 0) {
        *(char *)(iVar5 + 0x62) = '\x01' - *(char *)(iVar5 + 0x62);
        *(short *)(iVar5 + 0x44) = (short)*(char *)(iVar5 + 0x62);
        if (*(short *)(*(int *)(iVar6 + 0x6c) + iVar3 * 2) == -1) {
          param_1 = (double)FUN_8007d858();
          iVar3 = 0;
        }
        FUN_80024f40(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(short *)(*(int *)(iVar6 + 0x6c) + iVar3 * 2),(int)(short)iVar3,
                     *(undefined4 *)(iVar5 + (uint)*(ushort *)(iVar5 + 0x44) * 4 + 0x1c),iVar6);
      }
      iVar6 = *(int *)(iVar5 + (uint)*(ushort *)(iVar5 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(iVar5 + 0x34) = iVar6 + 6;
    *(byte *)(iVar5 + 0x60) = *(byte *)(iVar6 + 1) & 0xf0;
    *(float *)(iVar5 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar5 + 0x34) + 1)) -
                DOUBLE_803df568);
    if (*(char *)(iVar5 + 0x60) == '\0') {
      *(float *)(iVar5 + 0x14) = *(float *)(iVar5 + 0x14) - FLOAT_803df560;
    }
    uVar2 = (int)*(char *)(iVar6 + 1) & 0xf;
    if (uVar2 != 0) {
      *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
      *(short *)(iVar5 + 0x5e) =
           (short)(int)(FLOAT_803df574 /
                       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df580));
      *(undefined2 *)(iVar5 + 0x58) = 0x4000;
    }
    *(float *)(iVar5 + 0xc) = FLOAT_803df570;
    *(float *)(iVar5 + 4) = (float)(dVar7 * (double)*(float *)(iVar5 + 0x14));
  }
  return 0;
}
