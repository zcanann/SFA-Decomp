// Function: FUN_801b13f0
// Entry: 801b13f0
// Size: 1304 bytes

/* WARNING: Removing unreachable block (ram,0x801b18e0) */
/* WARNING: Removing unreachable block (ram,0x801b18d8) */
/* WARNING: Removing unreachable block (ram,0x801b1408) */
/* WARNING: Removing unreachable block (ram,0x801b1400) */

void FUN_801b13f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  byte bVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short sVar9;
  uint uVar10;
  int *piVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  short local_c8;
  short local_c4;
  short local_c2;
  undefined8 local_50;
  undefined8 local_40;
  
  piVar11 = *(int **)(param_9 + 0xb8);
  iVar7 = FUN_8002bac4();
  bVar5 = DAT_803dc070;
  if (*piVar11 == 0) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    uVar10 = (uint)DAT_803dc070;
    sVar6 = (short)piVar11[2];
    iVar8 = (int)DAT_803dcb50;
    if ((int)sVar6 < iVar8 + -1) {
      local_c8 = sVar6 + -1;
      if (local_c8 < 0) {
        local_c8 = 0;
      }
      sVar9 = (short)(iVar8 + -1);
      local_c4 = sVar6 + 1;
      if (iVar8 <= (short)(sVar6 + 1)) {
        local_c4 = sVar9;
      }
      local_c2 = sVar6 + 2;
      if (iVar8 <= (short)(sVar6 + 2)) {
        local_c2 = sVar9;
      }
      iVar8 = (short)(sVar6 * 3) * 2;
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324800 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * FLOAT_803e54e4;
      dVar14 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80324802 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e54f0) * FLOAT_803e54e4);
      fVar2 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324804 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * FLOAT_803e54e4;
      iVar8 = (short)(local_c4 * 3) * 2;
      fVar3 = (float)((double)CONCAT44(0x43300000,
                                       (int)*(short *)(&DAT_80324800 + iVar8) ^ 0x80000000) -
                     DOUBLE_803e54f0) * FLOAT_803e54e4;
      dVar15 = (double)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(&DAT_80324802 + iVar8) ^ 0x80000000
                                                ) - DOUBLE_803e54f0) * FLOAT_803e54e4);
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_80324804 + iVar8) ^ 0x80000000);
      fVar4 = (float)(local_50 - DOUBLE_803e54f0) * FLOAT_803e54e4;
      local_40 = (double)CONCAT44(0x43300000,
                                  (int)*(short *)(&DAT_80324802 + (short)(local_c2 * 3) * 2) ^
                                  0x80000000);
      if ((((float)(dVar15 - (double)((float)(local_40 - DOUBLE_803e54f0) * FLOAT_803e54e4)) <=
            FLOAT_803e54e8) &&
          ((float)(dVar14 - (double)((float)((double)CONCAT44(0x43300000,
                                                              (int)*(short *)(&DAT_80324802 +
                                                                             (short)(local_c8 * 3) *
                                                                             2) ^ 0x80000000) -
                                            DOUBLE_803e54f0) * FLOAT_803e54e4)) <= FLOAT_803e54e8))
         && (*(char *)(piVar11 + 3) < '\x01')) {
        FUN_80293900((double)(*(float *)(param_9 + 0x2c) * *(float *)(param_9 + 0x2c) +
                             *(float *)(param_9 + 0x24) * *(float *)(param_9 + 0x24) +
                             *(float *)(param_9 + 0x28) * *(float *)(param_9 + 0x28)));
        if ((*(ushort *)(iVar7 + 0xb0) & 0x1000) == 0) {
          FUN_8000bb38(param_9,0x1fb);
        }
        *(undefined *)(piVar11 + 3) = 0x1e;
      }
      dVar13 = (double)fVar1;
      dVar12 = (double)FLOAT_803e54e8;
      *(float *)(param_9 + 0xc) = (float)(dVar12 * (double)(float)((double)fVar3 - dVar13) + dVar13)
      ;
      *(float *)(param_9 + 0x10) = (float)(dVar12 * (double)(float)(dVar15 - dVar14) + dVar14);
      dVar14 = (double)fVar2;
      *(float *)(param_9 + 0x14) =
           (float)(dVar12 * (double)(float)((double)fVar4 - dVar14) + dVar14);
      *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0xc) + *(float *)(*piVar11 + 0xc);
      *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) + *(float *)(*piVar11 + 0x10);
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + *(float *)(*piVar11 + 0x14);
      *(float *)(param_9 + 0x24) =
           FLOAT_803dc078 * (*(float *)(param_9 + 0xc) - *(float *)(param_9 + 0x80));
      *(float *)(param_9 + 0x28) =
           FLOAT_803dc078 * (*(float *)(param_9 + 0x10) - *(float *)(param_9 + 0x84));
      *(float *)(param_9 + 0x2c) =
           FLOAT_803dc078 * (*(float *)(param_9 + 0x14) - *(float *)(param_9 + 0x88));
      piVar11[2] = piVar11[2] + uVar10;
      if ('\0' < *(char *)(piVar11 + 3)) {
        *(byte *)(piVar11 + 3) = *(char *)(piVar11 + 3) - bVar5;
      }
      dVar14 = DOUBLE_803e54f0;
      fVar1 = FLOAT_803e54ec;
      *(short *)(param_9 + 2) =
           (short)(int)-(FLOAT_803e54ec * -*(float *)(param_9 + 0x2c) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_9 + 2) ^ 0x80000000) -
                               DOUBLE_803e54f0));
      *(short *)(param_9 + 4) =
           (short)(int)-(fVar1 * *(float *)(param_9 + 0x24) -
                        (float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_9 + 4) ^ 0x80000000) - dVar14
                               ));
      iVar7 = *(int *)(param_9 + 0x54);
      if (iVar7 != 0) {
        *(ushort *)(iVar7 + 0x60) = *(ushort *)(iVar7 + 0x60) | 1;
        *(undefined *)(iVar7 + 0x6e) = 4;
        *(undefined *)(iVar7 + 0x6f) = 2;
        *(undefined4 *)(iVar7 + 0x48) = 0x10;
        *(undefined4 *)(iVar7 + 0x4c) = 0x10;
      }
    }
    else {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

