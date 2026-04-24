// Function: FUN_801d359c
// Entry: 801d359c
// Size: 672 bytes

void FUN_801d359c(int param_1,int param_2)

{
  short sVar1;
  int iVar2;
  undefined2 uVar4;
  uint uVar3;
  int iVar5;
  double dVar6;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  sVar1 = *(short *)(iVar5 + 0x1c);
  iVar2 = FUN_800221a0(0,100);
  if ((iVar2 < 10) && (*(float *)(param_2 + 0x2a0) <= FLOAT_803e5394)) {
    uVar4 = FUN_800221a0(2000,4000);
    *(undefined2 *)(param_2 + 0x2ac) = uVar4;
    iVar2 = FUN_800221a0(0,1);
    if (iVar2 != 0) {
      *(short *)(param_2 + 0x2ac) = -*(short *)(param_2 + 0x2ac);
    }
    *(short *)(param_2 + 0x2ac) = *(short *)(param_2 + 0x2ac) + *(short *)(param_2 + 0x2a8);
    iVar2 = (int)*(short *)(param_2 + 0x2ac) - ((int)sVar1 & 0xffffU);
    if (0x8000 < iVar2) {
      iVar2 = iVar2 + -0xffff;
    }
    if (iVar2 < -0x8000) {
      iVar2 = iVar2 + 0xffff;
    }
    if (*(short *)(iVar5 + 0x1a) < iVar2) {
      *(short *)(param_2 + 0x2ac) = sVar1 + *(short *)(iVar5 + 0x1a);
    }
    if (iVar2 < -(int)*(short *)(iVar5 + 0x1a)) {
      *(short *)(param_2 + 0x2ac) = sVar1 - *(short *)(iVar5 + 0x1a);
    }
    *(float *)(param_2 + 0x2a0) = FLOAT_803e53a8;
  }
  iVar2 = FUN_800221a0(0,100);
  if ((iVar2 < 10) && (*(float *)(param_2 + 0x2a0) <= FLOAT_803e5394)) {
    uVar3 = FUN_800221a0(0xffffff38,200);
    *(float *)(param_2 + 0x280) =
         *(float *)(param_2 + 0x278) +
         (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e53a0) / FLOAT_803e5390
    ;
    if (FLOAT_803e53ac <= *(float *)(param_2 + 0x280)) {
      if (FLOAT_803e53b0 < *(float *)(param_2 + 0x280)) {
        *(float *)(param_2 + 0x280) = FLOAT_803e53b0;
      }
    }
    else {
      *(float *)(param_2 + 0x280) = FLOAT_803e53ac;
    }
  }
  iVar2 = (int)*(short *)(param_2 + 0x2ac) - ((int)*(short *)(param_2 + 0x2a8) & 0xffffU);
  if (0x8000 < iVar2) {
    iVar2 = iVar2 + -0xffff;
  }
  if (iVar2 < -0x8000) {
    iVar2 = iVar2 + 0xffff;
  }
  *(short *)(param_2 + 0x2a8) =
       *(short *)(param_2 + 0x2a8) + (short)((int)(iVar2 * (uint)DAT_803db410) >> 4);
  *(float *)(param_2 + 0x278) =
       FLOAT_803e53b4 * (*(float *)(param_2 + 0x280) - *(float *)(param_2 + 0x278)) * FLOAT_803db414
       + *(float *)(param_2 + 0x278);
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e5398 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x2a8) ^
                                                                 0x80000000) - DOUBLE_803e53a0)) /
                                       FLOAT_803e539c));
  *(float *)(param_2 + 0x288) = (float)((double)*(float *)(param_2 + 0x278) * dVar6);
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e5398 *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*(short *)(param_2 + 0x2a8) ^
                                                                 0x80000000) - DOUBLE_803e53a0)) /
                                       FLOAT_803e539c));
  *(float *)(param_2 + 0x28c) = (float)((double)*(float *)(param_2 + 0x278) * dVar6);
  return;
}

