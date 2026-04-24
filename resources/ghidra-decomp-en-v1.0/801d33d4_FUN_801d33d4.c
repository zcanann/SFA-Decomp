// Function: FUN_801d33d4
// Entry: 801d33d4
// Size: 456 bytes

void FUN_801d33d4(int param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  sVar1 = *(short *)(iVar5 + 0x1c);
  uVar2 = FUN_800221a0(0x1e,0x2d);
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e53a0);
  uVar2 = FUN_800221a0(0x78,0xb4);
  *(float *)(param_2 + 0x284) =
       *(float *)(param_2 + 0x298) +
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e53a0);
  sVar3 = FUN_800221a0(0xfffff830,2000);
  *(short *)(param_2 + 0x2aa) = *(short *)(param_2 + 0x2a8) + sVar3;
  iVar4 = (int)*(short *)(param_2 + 0x2aa) - ((int)sVar1 & 0xffffU);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  if (*(short *)(iVar5 + 0x1a) < iVar4) {
    *(short *)(param_2 + 0x2aa) = sVar1 + *(short *)(iVar5 + 0x1a);
  }
  if (iVar4 < -(int)*(short *)(iVar5 + 0x1a)) {
    *(short *)(param_2 + 0x2aa) = sVar1 - *(short *)(iVar5 + 0x1a);
  }
  uVar2 = FUN_800221a0(900,0x514);
  dVar6 = DOUBLE_803e53a0;
  *(float *)(param_2 + 0x29c) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e53a0) / FLOAT_803e5390;
  *(float *)(param_2 + 0x27c) = FLOAT_803e5394;
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e5398 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x2aa) ^
                                                                 0x80000000) - dVar6)) /
                                       FLOAT_803e539c));
  *(float *)(param_2 + 0x290) = (float)dVar6;
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e5398 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x2aa) ^
                                                                 0x80000000) - DOUBLE_803e53a0)) /
                                       FLOAT_803e539c));
  *(float *)(param_2 + 0x294) = (float)dVar6;
  return;
}

