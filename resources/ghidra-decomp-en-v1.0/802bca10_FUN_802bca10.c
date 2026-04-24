// Function: FUN_802bca10
// Entry: 802bca10
// Size: 748 bytes

void FUN_802bca10(undefined4 param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  double dVar3;
  short sVar4;
  short *psVar5;
  undefined2 *puVar6;
  int iVar7;
  uint uVar8;
  
  dVar3 = DOUBLE_803e82e0;
  iVar7 = *(int *)(param_2 + 0x480) << 1;
  if (iVar7 < -0x41) {
    iVar7 = -0x41;
  }
  else if (0x41 < iVar7) {
    iVar7 = 0x41;
  }
  uVar8 = iVar7 * 0xb6 - ((int)*(short *)(param_2 + 0x4d4) & 0xffffU);
  if (0x8000 < (int)uVar8) {
    uVar8 = uVar8 - 0xffff;
  }
  if ((int)uVar8 < -0x8000) {
    uVar8 = uVar8 + 0xffff;
  }
  uVar8 = (uint)((float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e82e0) *
                FLOAT_803e8324);
  if ((int)uVar8 < -0x16c) {
    uVar8 = 0xfffffe94;
  }
  else if (0x16c < (int)uVar8) {
    uVar8 = 0x16c;
  }
  *(short *)(param_2 + 0x4d4) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e82e0) *
                    FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x4d4) ^ 0x80000000
                                           ) - DOUBLE_803e82e0));
  *(short *)(param_2 + 0x4d2) = *(short *)(param_2 + 0x4d4) / 2;
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x19c) ^ 0x80000000) - dVar3
                 ) / FLOAT_803e8328;
  fVar2 = FLOAT_803e8334;
  if ((FLOAT_803e8334 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8338 < fVar1)) {
    fVar2 = FLOAT_803e8338;
  }
  iVar7 = (int)(FLOAT_803e832c * FLOAT_803e8330 * -fVar2) -
          ((int)*(short *)(param_2 + 0x4d6) & 0xffffU);
  if (0x8000 < iVar7) {
    iVar7 = iVar7 + -0xffff;
  }
  if (iVar7 < -0x8000) {
    iVar7 = iVar7 + 0xffff;
  }
  *(short *)(param_2 + 0x4d6) = *(short *)(param_2 + 0x4d6) + (short)iVar7;
  psVar5 = (short *)FUN_800395d8(param_1,0);
  puVar6 = (undefined2 *)FUN_800395d8(param_1,9);
  FUN_800395d8(param_1,4);
  FUN_800395d8(param_1,5);
  if (psVar5 != (short *)0x0) {
    *psVar5 = -*(short *)(param_2 + 0x4d6);
    psVar5[1] = *(short *)(param_2 + 0x4d4) / 2;
    sVar4 = psVar5[1];
    if (sVar4 < -4000) {
      sVar4 = -4000;
    }
    else if (4000 < sVar4) {
      sVar4 = 4000;
    }
    psVar5[1] = sVar4;
    psVar5[2] = 0;
  }
  if (puVar6 != (undefined2 *)0x0) {
    puVar6[1] = *(undefined2 *)(param_2 + 0x4d2);
    sVar4 = puVar6[1];
    if (sVar4 < -3000) {
      sVar4 = -3000;
    }
    else if (3000 < sVar4) {
      sVar4 = 3000;
    }
    puVar6[1] = sVar4;
    iVar7 = (int)*(short *)(param_2 + 0x4d2);
    if (iVar7 < 0) {
      iVar7 = -iVar7;
    }
    *puVar6 = (short)(iVar7 >> 1);
  }
  return;
}

