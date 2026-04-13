// Function: FUN_801b2338
// Entry: 801b2338
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x801b2370) */

void FUN_801b2338(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_9 + 0x5c);
  if ((*(char *)(piVar3 + 2) != '\x01') && (*(char *)(piVar3 + 2) == '\0')) {
    param_4 = (double)*(float *)(param_9 + 0x14);
    *(float *)(param_9 + 0x14) =
         (float)((double)(FLOAT_803e553c * -FLOAT_803dcb58) * (double)FLOAT_803dc074 + param_4);
    param_1 = (double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074);
    param_2 = (double)(FLOAT_803e5540 * (float)(param_4 + (double)*(float *)(param_9 + 0x14)) *
                      FLOAT_803dc074);
    param_3 = (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074);
    FUN_8002ba34(param_1,param_2,param_3,(int)param_9);
    param_9[2] = param_9[2] + *(char *)((int)piVar3 + 9) * 10;
    param_9[1] = param_9[1] + *(char *)((int)piVar3 + 10) * 10;
    *param_9 = *param_9 + *(char *)((int)piVar3 + 0xb) * 10;
    iVar2 = *(int *)(param_9 + 0x2a);
    if (iVar2 != 0) {
      param_1 = (double)FUN_80035eec((int)param_9,5,*(undefined *)((int)piVar3 + 6),0);
      iVar2 = *(int *)(iVar2 + 0x50);
      if ((iVar2 != 0) && (iVar2 != *piVar3)) {
        FUN_80035a6c((int)param_9,(ushort)*(byte *)((int)piVar3 + 5));
        param_1 = (double)FUN_8009adfc((double)FLOAT_803e5538,param_2,param_3,param_4,param_5,
                                       param_6,param_7,param_8,param_9,2,1,0,1,1,1,0);
        param_9[0x7a] = 0;
        param_9[0x7b] = 0x49c;
        *(undefined *)(piVar3 + 2) = 1;
        param_9[3] = param_9[3] | 0x4000;
      }
    }
    uVar1 = FUN_80020078(0x85e);
    if (((uVar1 != 0) && (uVar1 = FUN_80020078(0xc2d), uVar1 == 0)) ||
       ((uVar1 = FUN_80020078(0x874), uVar1 != 0 && (uVar1 = FUN_80020078(0xc2e), uVar1 == 0)))) {
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x4b0;
    }
    if (*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') {
      FUN_80035a6c((int)param_9,(ushort)*(byte *)((int)piVar3 + 5));
      param_1 = (double)FUN_8009adfc((double)FLOAT_803e5538,param_2,param_3,param_4,param_5,param_6,
                                     param_7,param_8,param_9,2,1,0,1,1,1,0);
      param_9[0x7a] = 0;
      param_9[0x7b] = 0x49c;
      *(undefined *)(piVar3 + 2) = 1;
      param_9[3] = param_9[3] | 0x4000;
    }
  }
  *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) + (uint)DAT_803dc070;
  if (*(int *)(param_9 + 0x7a) < 0x4b1) {
    if (*(char *)((int)piVar3 + 7) != '\0') {
      *(undefined *)((int)piVar3 + 7) = 0;
    }
  }
  else {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

