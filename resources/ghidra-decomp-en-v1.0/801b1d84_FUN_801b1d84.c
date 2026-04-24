// Function: FUN_801b1d84
// Entry: 801b1d84
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x801b1dbc) */

void FUN_801b1d84(short *param_1)

{
  float fVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  if ((*(char *)(piVar3 + 2) != '\x01') && (*(char *)(piVar3 + 2) == '\0')) {
    fVar1 = *(float *)(param_1 + 0x14);
    *(float *)(param_1 + 0x14) = FLOAT_803e48a4 * -FLOAT_803dbef0 * FLOAT_803db414 + fVar1;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(FLOAT_803e48a8 * (fVar1 + *(float *)(param_1 + 0x14)) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414));
    param_1[2] = param_1[2] + *(char *)((int)piVar3 + 9) * 10;
    param_1[1] = param_1[1] + *(char *)((int)piVar3 + 10) * 10;
    *param_1 = *param_1 + *(char *)((int)piVar3 + 0xb) * 10;
    iVar2 = *(int *)(param_1 + 0x2a);
    if (iVar2 != 0) {
      FUN_80035df4(param_1,5,*(undefined *)((int)piVar3 + 6),0);
      iVar2 = *(int *)(iVar2 + 0x50);
      if ((iVar2 != 0) && (iVar2 != *piVar3)) {
        FUN_80035974(param_1,*(undefined *)((int)piVar3 + 5));
        FUN_8009ab70((double)FLOAT_803e48a0,param_1,2,1,0,1,1,1,0);
        *(undefined4 *)(param_1 + 0x7a) = 0x49c;
        *(undefined *)(piVar3 + 2) = 1;
        param_1[3] = param_1[3] | 0x4000;
      }
    }
    iVar2 = FUN_8001ffb4(0x85e);
    if (((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0xc2d), iVar2 == 0)) ||
       ((iVar2 = FUN_8001ffb4(0x874), iVar2 != 0 && (iVar2 = FUN_8001ffb4(0xc2e), iVar2 == 0)))) {
      *(undefined4 *)(param_1 + 0x7a) = 0x4b0;
    }
    if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') {
      FUN_80035974(param_1,*(undefined *)((int)piVar3 + 5));
      FUN_8009ab70((double)FLOAT_803e48a0,param_1,2,1,0,1,1,1,0);
      *(undefined4 *)(param_1 + 0x7a) = 0x49c;
      *(undefined *)(piVar3 + 2) = 1;
      param_1[3] = param_1[3] | 0x4000;
    }
  }
  *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) + (uint)DAT_803db410;
  if (*(int *)(param_1 + 0x7a) < 0x4b1) {
    if (*(char *)((int)piVar3 + 7) != '\0') {
      *(undefined *)((int)piVar3 + 7) = 0;
    }
  }
  else {
    FUN_8002cbc4(param_1);
  }
  return;
}

