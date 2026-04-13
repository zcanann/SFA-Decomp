// Function: FUN_801469b4
// Entry: 801469b4
// Size: 500 bytes

void FUN_801469b4(int param_1)

{
  float fVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  int local_18 [2];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84);
  if (fVar1 < FLOAT_803e306c) {
    fVar1 = -fVar1;
  }
  if (FLOAT_803e3078 == fVar1) {
    if (*(float *)(param_1 + 0x10) == *(float *)(param_1 + 0x1c)) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf | 0x20;
      *(undefined4 *)(iVar4 + 0x5c) = 0xffffffff;
      *(float *)(iVar4 + 0x60) = FLOAT_803e306c;
    }
  }
  else {
    iVar3 = FUN_8002e1ac(0x46406);
    if ((iVar3 != 0) &&
       (dVar5 = FUN_80021730((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18)),
       dVar5 < (double)FLOAT_803e31d0)) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf | 0x20;
      *(undefined4 *)(iVar4 + 0x5c) = 0x46406;
      *(float *)(iVar4 + 0x60) = FLOAT_803e306c;
    }
  }
  if ((*(byte *)(iVar4 + 0x58) >> 5 & 1) != 0) {
    piVar2 = FUN_80037048(0x51,local_18);
    for (iVar3 = 0; iVar3 < local_18[0]; iVar3 = iVar3 + 1) {
      dVar5 = FUN_80194e3c(*piVar2,3);
      if (*(int *)(iVar4 + 0x5c) == -1) {
        fVar1 = (float)(dVar5 - (double)*(float *)(param_1 + 0x10));
        if (fVar1 < FLOAT_803e306c) {
          fVar1 = -fVar1;
        }
        if (fVar1 < FLOAT_803e3148) {
          *(undefined4 *)(iVar4 + 0x5c) = *(undefined4 *)(*(int *)(*piVar2 + 0x4c) + 0x14);
        }
      }
      if (*(int *)(iVar4 + 0x5c) == *(int *)(*(int *)(*piVar2 + 0x4c) + 0x14)) {
        if (((double)*(float *)(iVar4 + 0x60) == (double)FLOAT_803e306c) ||
           ((double)*(float *)(iVar4 + 0x60) != dVar5)) {
          *(float *)(param_1 + 0x10) = (float)dVar5;
          *(float *)(iVar4 + 0x60) = (float)dVar5;
        }
        else {
          *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf;
        }
        break;
      }
      piVar2 = piVar2 + 1;
    }
    if (iVar3 == local_18[0]) {
      *(byte *)(iVar4 + 0x58) = *(byte *)(iVar4 + 0x58) & 0xdf;
    }
  }
  return;
}

