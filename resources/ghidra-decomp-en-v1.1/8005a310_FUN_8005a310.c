// Function: FUN_8005a310
// Entry: 8005a310
// Size: 712 bytes

/* WARNING: Removing unreachable block (ram,0x8005a5b8) */
/* WARNING: Removing unreachable block (ram,0x8005a320) */

undefined4 FUN_8005a310(int param_1)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float fStack_48;
  float fStack_44;
  float local_40;
  float fStack_3c;
  undefined auStack_38 [4];
  undefined auStack_34 [4];
  undefined8 local_30;
  
  if (*(byte *)(param_1 + 0x36) == 0) {
    *(undefined *)(param_1 + 0x37) = 0;
    return 0;
  }
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 1) == 0)) {
    dVar9 = (double)*(float *)(param_1 + 0x40);
    if (dVar9 < (double)FLOAT_803df838) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    iVar2 = FUN_8002bac4();
    if (((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 2) == 0)) || (iVar2 == 0)) {
      dVar8 = (double)FUN_8000f4a0((double)*(float *)(param_1 + 0x18),
                                   (double)*(float *)(param_1 + 0x1c),
                                   (double)*(float *)(param_1 + 0x20));
    }
    else {
      dVar8 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    }
    if (dVar9 < dVar8) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    uVar6 = 0xff;
    dVar7 = (double)(float)(dVar9 - (double)FLOAT_803df854);
    if (dVar7 < dVar8) {
      uVar6 = (uint)(FLOAT_803df858 *
                    (FLOAT_803df85c - (float)(dVar8 - dVar7) / (float)(dVar9 - dVar7)));
      local_30 = (double)(longlong)(int)uVar6;
    }
    FUN_8000eba8((double)(*(float *)(param_1 + 0x18) - FLOAT_803dda58),
                 (double)*(float *)(param_1 + 0x1c),
                 (double)(*(float *)(param_1 + 0x20) - FLOAT_803dda5c),
                 (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),auStack_34,
                 auStack_38,&fStack_3c,&local_40,&fStack_44,&fStack_48);
    fVar1 = ABS(local_40) * FLOAT_803df834;
    if (fVar1 < FLOAT_803df860) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    if (fVar1 < FLOAT_803df868) {
      local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)(((float)(local_30 - DOUBLE_803df840) * (fVar1 - FLOAT_803df860)) /
                    FLOAT_803df864);
    }
    *(char *)(param_1 + 0x37) = (char)(uVar6 * (*(byte *)(param_1 + 0x36) + 1) >> 8);
  }
  else {
    *(char *)(param_1 + 0x37) = (char)((*(byte *)(param_1 + 0x36) + 1) * 0xff >> 8);
  }
  if (*(char *)(param_1 + 0x37) == '\0') {
    uVar3 = 0;
  }
  else {
    for (bVar4 = 0; bVar4 < 5; bVar4 = bVar4 + 1) {
      uVar6 = (uint)bVar4;
      if (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8) +
          (float)(&DAT_803885a8)[uVar6 * 5] +
          (float)(&DAT_803885a4)[uVar6 * 5] * (*(float *)(param_1 + 0x20) - FLOAT_803dda5c) +
          *(float *)(param_1 + 0x1c) * (float)(&DAT_803885a0)[uVar6 * 5] +
          (float)(&DAT_8038859c)[uVar6 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dda58) <
          FLOAT_803df84c) {
        return 0;
      }
    }
    uVar3 = 1;
  }
  return uVar3;
}

