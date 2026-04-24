#include "ghidra_import.h"
#include "main/dll/tFrameAnimator.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8002a6b4();
extern undefined4 FUN_8002ba34();
extern undefined4 FUN_80036018();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80137cd0();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80293900();

extern undefined4* DAT_803dd728;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4334;
extern f32 FLOAT_803e4338;
extern f32 FLOAT_803e4348;
extern f32 FLOAT_803e434c;
extern f32 FLOAT_803e4350;
extern f32 FLOAT_803e4354;
extern f32 FLOAT_803e4358;
extern f32 FLOAT_803e435c;
extern f32 FLOAT_803e4360;
extern f32 FLOAT_803e4364;
extern f32 FLOAT_803e4368;
extern f32 FLOAT_803e436c;

/*
 * --INFO--
 *
 * Function: FUN_80179f40
 * EN v1.0 Address: 0x80179EB0
 * EN v1.0 Size: 1220b
 * EN v1.1 Address: 0x80179F40
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80179f40(ushort *param_1)
{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  bool bVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  float local_88;
  float local_84;
  float local_80;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  dVar10 = (double)FLOAT_803e4348;
  FUN_80036018((int)param_1);
  fVar2 = *(float *)(iVar5 + 0x2b4) - *(float *)(param_1 + 8);
  if (fVar2 < FLOAT_803e4334) {
    fVar2 = -fVar2;
  }
  fVar3 = *(float *)(iVar5 + 0x2b0) - *(float *)(param_1 + 6);
  if (fVar3 < FLOAT_803e4334) {
    fVar3 = -fVar3;
  }
  fVar4 = *(float *)(iVar5 + 0x2b8) - *(float *)(param_1 + 10);
  if (fVar4 < FLOAT_803e4334) {
    fVar4 = -fVar4;
  }
  bVar6 = fVar4 + fVar3 + fVar2 < FLOAT_803e434c;
  if (!bVar6) {
    FUN_80247eb8((float *)(param_1 + 6),(float *)(iVar5 + 0x2b0),&local_88);
    dVar10 = (double)FLOAT_803e4348;
  }
  if (*(float *)(iVar5 + 0x1b4) <= FLOAT_803e4334) {
    fVar2 = *(float *)(iVar5 + 0x2c0);
    if (fVar2 != FLOAT_803e4334) {
      if (*(float *)(param_1 + 8) <= fVar2) {
        *(float *)(iVar5 + 0x2c4) = fVar2 - *(float *)(param_1 + 8);
        bVar1 = true;
        goto LAB_8017a09c;
      }
      *(float *)(iVar5 + 0x2c0) = FLOAT_803e4334;
    }
    bVar1 = false;
  }
  else {
    *(undefined4 *)(iVar5 + 0x2c0) = *(undefined4 *)(iVar5 + 0x1bc);
    *(undefined4 *)(iVar5 + 0x2c4) = *(undefined4 *)(iVar5 + 0x1b4);
    bVar1 = true;
  }
LAB_8017a09c:
  fVar2 = FLOAT_803e4350;
  if (bVar1) {
    *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4350;
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * fVar2;
    *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
    *(float *)(param_1 + 0x14) = FLOAT_803e4354 * FLOAT_803dc074 + *(float *)(param_1 + 0x14);
    FUN_8007d858();
    if (((*(float *)(param_1 + 0x14) < FLOAT_803e4358) &&
        (FLOAT_803e435c < *(float *)(param_1 + 0x14))) &&
       (*(float *)(iVar5 + 0x2c4) < FLOAT_803e4338)) {
      return 1;
    }
  }
  else if (bVar6) {
    *(float *)(param_1 + 0x14) = -(FLOAT_803e4360 * FLOAT_803dc074 - *(float *)(param_1 + 0x14));
  }
  FUN_8002ba34((double)(*(float *)(param_1 + 0x12) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x14) * FLOAT_803dc074),
               (double)(*(float *)(param_1 + 0x16) * FLOAT_803dc074),(int)param_1);
  if (*(char *)(*(int *)(param_1 + 0x5c) + 0x25b) == '\x01') {
    (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,iVar5);
    (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar5);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,iVar5);
  }
  else {
    (**(code **)(*DAT_803dd728 + 0x20))(param_1);
  }
  bVar1 = *(char *)(iVar5 + 0x261) != '\0';
  if (bVar1) {
    local_88 = *(float *)(iVar5 + 0x68);
    local_84 = *(float *)(iVar5 + 0x6c);
    local_80 = *(float *)(iVar5 + 0x70);
  }
  if (bVar1 || !bVar6) {
    FUN_80247ef8(&local_88,&local_88);
    dVar13 = -(double)*(float *)(param_1 + 0x12);
    dVar12 = -(double)*(float *)(param_1 + 0x14);
    dVar11 = -(double)*(float *)(param_1 + 0x16);
    dVar8 = FUN_80293900((double)(float)(dVar11 * dVar11 +
                                        (double)(float)(dVar13 * dVar13 +
                                                       (double)(float)(dVar12 * dVar12))));
    if ((double)FLOAT_803e4364 < dVar8) {
      FUN_8000bb38((uint)param_1,0x16c);
    }
    if ((double)FLOAT_803e4334 != dVar8) {
      dVar7 = (double)(float)((double)FLOAT_803e4338 / dVar8);
      dVar13 = (double)(float)(dVar13 * dVar7);
      dVar12 = (double)(float)(dVar12 * dVar7);
      dVar11 = (double)(float)(dVar11 * dVar7);
    }
    dVar9 = (double)(FLOAT_803e4368 *
                    (float)(dVar11 * (double)local_80 +
                           (double)(float)(dVar13 * (double)local_88 +
                                          (double)(float)(dVar12 * (double)local_84))));
    FUN_80137cd0();
    dVar7 = (double)FLOAT_803e4334;
    if (dVar7 < dVar9) {
      *(float *)(param_1 + 0x12) = (float)((double)local_88 * dVar9);
      *(float *)(param_1 + 0x14) = (float)((double)local_84 * dVar9);
      *(float *)(param_1 + 0x16) = (float)((double)local_80 * dVar9);
      *(float *)(param_1 + 0x12) = (float)((double)*(float *)(param_1 + 0x12) - dVar13);
      *(float *)(param_1 + 0x14) = (float)((double)*(float *)(param_1 + 0x14) - dVar12);
      *(float *)(param_1 + 0x16) = (float)((double)*(float *)(param_1 + 0x16) - dVar11);
      if ((((double)*(float *)(iVar5 + 0x2c0) == dVar7) && (dVar8 < (double)FLOAT_803e436c)) &&
         (*(char *)(iVar5 + 0x261) != '\0')) {
        return 2;
      }
      FUN_80247edc((double)(float)(dVar8 * dVar10),(float *)(param_1 + 0x12),
                   (float *)(param_1 + 0x12));
    }
  }
  if (!bVar6) {
    *(float *)(param_1 + 0x14) = -(FLOAT_803e4360 * FLOAT_803dc074 - *(float *)(param_1 + 0x14));
  }
  FUN_8002a6b4(param_1);
  *(undefined4 *)(iVar5 + 0x2b0) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(iVar5 + 0x2b4) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(iVar5 + 0x2b8) = *(undefined4 *)(param_1 + 10);
  return 3;
}
