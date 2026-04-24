// Function: FUN_80059e2c
// Entry: 80059e2c
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x8005a03c) */
/* WARNING: Removing unreachable block (ram,0x8005a034) */
/* WARNING: Removing unreachable block (ram,0x80059e44) */
/* WARNING: Removing unreachable block (ram,0x80059e3c) */

void FUN_80059e2c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  
  iVar3 = FUN_80286840();
  bVar1 = false;
  uVar10 = extraout_f1;
  while (iVar4 = FUN_8004319c(), iVar4 != 0) {
    uVar10 = FUN_80014f6c();
    FUN_80020390();
    if (bVar1) {
      uVar10 = FUN_8004a9e4();
    }
    uVar10 = FUN_80048350(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (bVar1) {
      uVar10 = FUN_800235b0();
      uVar10 = FUN_80019c5c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004a5b8('\x01');
    }
    if (DAT_803dd5d0 != '\0') {
      bVar1 = true;
    }
  }
  iVar4 = 0;
  for (piVar5 = &DAT_80382eac; (iVar4 < DAT_803dda6c && (*piVar5 != 0)); piVar5 = piVar5 + 2) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 == DAT_803dda6c) {
    DAT_803dda6c = DAT_803dda6c + '\x01';
  }
  iVar6 = FUN_8005a05c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  (&DAT_80382eac)[iVar4 * 2] = iVar6;
  (&DAT_803870c8)[iVar3] = iVar6;
  (&DAT_80382eb0)[iVar4 * 4] = (short)iVar3;
  DAT_803ddb20 = (&DAT_80382eac)[iVar4 * 2];
  psVar8 = (short *)(DAT_80382e9c + iVar3 * 10);
  *(undefined *)(DAT_803ddb20 + 0x19) = *(undefined *)(DAT_80382ea4 + iVar3);
  dVar11 = DOUBLE_803df840;
  fVar2 = FLOAT_803df834;
  *(float *)(DAT_803ddb20 + 0x24) =
       FLOAT_803df834 *
       (float)((double)CONCAT44(0x43300000,
                                (int)*psVar8 + (int)*(short *)(DAT_803ddb20 + 4) ^ 0x80000000) -
              DOUBLE_803df840);
  *(float *)(DAT_803ddb20 + 0x28) =
       fVar2 * (float)((double)CONCAT44(0x43300000,
                                        (int)psVar8[2] + (int)*(short *)(DAT_803ddb20 + 6) ^
                                        0x80000000) - dVar11);
  iVar4 = DAT_803ddb20;
  dVar11 = (double)*(float *)(DAT_803ddb20 + 0x28);
  dVar12 = (double)*(float *)(DAT_803ddb20 + 0x24);
  if (DAT_803ddb20 != 0) {
    iVar6 = *(int *)(DAT_803ddb20 + 0x20);
    for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar4 + 8); iVar9 = iVar9 + iVar7) {
      iVar7 = FUN_800e8384(iVar6);
      if (iVar7 == 0) {
        *(float *)(iVar6 + 8) = (float)((double)*(float *)(iVar6 + 8) + dVar12);
        *(float *)(iVar6 + 0x10) = (float)((double)*(float *)(iVar6 + 0x10) + dVar11);
      }
      iVar7 = (uint)*(byte *)(iVar6 + 2) * 4;
      iVar6 = iVar6 + iVar7;
    }
  }
  DAT_803dc280 = iVar3;
  FUN_8028688c();
  return;
}

