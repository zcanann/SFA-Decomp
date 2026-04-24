// Function: FUN_8015ffc8
// Entry: 8015ffc8
// Size: 440 bytes

void FUN_8015ffc8(short *param_1)

{
  int iVar1;
  
  *(int *)(param_1 + 0x7a) =
       (int)((float)((double)CONCAT44(0x43300000,*(uint *)(param_1 + 0x7a) ^ 0x80000000) -
                    DOUBLE_803e2e60) - FLOAT_803db414);
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_8002cbc4();
    return;
  }
  if (*(char *)(param_1 + 0x1b) != '\0') {
    *(float *)(param_1 + 0x14) = -(FLOAT_803e2e54 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803e2e58;
    *param_1 = *param_1 + 0x38e;
    param_1[2] = param_1[2] + 0x38e;
    param_1[1] = param_1[1] + 0x38e;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414));
    FUN_80035df4(param_1,10,1,0);
    FUN_80035974(param_1,5);
    FUN_80035f20(param_1);
    if ((*(int *)(*(int *)(param_1 + 0x2a) + 0x50) == 0) ||
       ((iVar1 = FUN_8002b9ec(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) != iVar1 &&
        (iVar1 = FUN_8002b9ac(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) != iVar1)))) {
      if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) != '\0') {
        FUN_8015fbec(param_1);
        *(undefined *)(param_1 + 0x1b) = 0;
        *(undefined4 *)(param_1 + 0x7a) = 0x78;
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
      }
    }
    else {
      FUN_8015fccc(param_1);
      *(undefined *)(param_1 + 0x1b) = 0;
      *(undefined4 *)(param_1 + 0x7a) = 0x78;
      *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    }
    return;
  }
  return;
}

