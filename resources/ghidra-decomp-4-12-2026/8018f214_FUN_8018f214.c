// Function: FUN_8018f214
// Entry: 8018f214
// Size: 840 bytes

void FUN_8018f214(short *param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  double dVar9;
  
  pfVar8 = *(float **)(param_1 + 0x5c);
  iVar7 = *(int *)(param_1 + 0x26);
  if (*(short *)((int)pfVar8 + 0x12) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
    iVar5 = FUN_8002bac4();
    if ((iVar5 != 0) && (iVar7 != 0)) {
      if ((*(char *)(iVar7 + 0x29) != '\0') && (*(char *)(iVar7 + 0x29) != -1)) {
        if (*(short *)((int)pfVar8 + 0x1a) < 1) {
          *(undefined2 *)(pfVar8 + 6) = 0;
          *(ushort *)((int)pfVar8 + 0x1a) = (ushort)*(byte *)(iVar7 + 0x29) * 100;
          if (*(ushort *)(iVar7 + 0x2a) != 0) {
            FUN_8000bb38((uint)param_1,*(ushort *)(iVar7 + 0x2a));
          }
        }
        else {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        *(ushort *)((int)pfVar8 + 0x1a) = *(short *)((int)pfVar8 + 0x1a) - (ushort)DAT_803dc070;
      }
      if (*(char *)(iVar7 + 0x27) == '\x7f') {
        *param_1 = *param_1 + (ushort)DAT_803dc070 * 10;
      }
      else {
        *param_1 = *param_1 + (short)*(char *)(iVar7 + 0x27) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x26) == '\x7f') {
        param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[1] = param_1[1] + (short)*(char *)(iVar7 + 0x26) * (ushort)DAT_803dc070 * 100;
      }
      if (*(char *)(iVar7 + 0x25) == '\x7f') {
        param_1[2] = param_1[2] + (ushort)DAT_803dc070 * 10;
      }
      else {
        param_1[2] = param_1[2] + (short)*(char *)(iVar7 + 0x25) * (ushort)DAT_803dc070 * 100;
      }
      if ((((int)*(short *)(pfVar8 + 5) == 0xffffffff) ||
          (uVar6 = FUN_80020078((int)*(short *)(pfVar8 + 5)), uVar6 != 0)) &&
         (*(short *)(pfVar8 + 6) == 0)) {
        if (((int)*(short *)((int)pfVar8 + 0x16) != 0xffffffff) &&
           (uVar6 = FUN_80020078((int)*(short *)((int)pfVar8 + 0x16)), uVar6 != 0)) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        if (*(char *)(iVar7 + 0x29) == -1) {
          *(undefined2 *)(pfVar8 + 6) = 1;
        }
        sVar1 = *(short *)((int)pfVar8 + 0xe);
        if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0x7a) < 1)))) {
          fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar5 + 0x18);
          fVar3 = *(float *)(param_1 + 0xe) - *(float *)(iVar5 + 0x1c);
          fVar4 = *(float *)(param_1 + 0x10) - *(float *)(iVar5 + 0x20);
          if (sVar1 == 0) {
            *(undefined2 *)(pfVar8 + 6) = 1;
          }
          dVar9 = FUN_80293900((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
          if ((dVar9 <= (double)*pfVar8) || ((double)FLOAT_803e4ae4 == (double)*pfVar8)) {
            FUN_8018ec40();
          }
          *(int *)(param_1 + 0x7a) = -(int)*(short *)((int)pfVar8 + 0xe);
        }
        else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
          *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
        }
      }
    }
  }
  else {
    *(short *)((int)pfVar8 + 0x12) = *(short *)((int)pfVar8 + 0x12) - (short)(int)FLOAT_803dc074;
    if (*(short *)((int)pfVar8 + 0x12) < 0) {
      *(undefined2 *)((int)pfVar8 + 0x12) = 0;
    }
  }
  return;
}

