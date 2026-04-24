// Function: FUN_801e43c0
// Entry: 801e43c0
// Size: 460 bytes

void FUN_801e43c0(undefined2 *param_1)

{
  int *piVar1;
  undefined auStack40 [8];
  float local_20;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  if (*piVar1 == 0) {
    *piVar1 = *(int *)(param_1 + 0x7c);
  }
  if (*piVar1 != 0) {
    *param_1 = 0;
    param_1[2] = param_1[2] + (ushort)DAT_803db410 * -800;
    *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803db410;
    if (*(int *)(param_1 + 0x7a) < 0) {
      FUN_8002cbc4(param_1);
    }
    else {
      if (*(char *)(piVar1 + 5) == '\0') {
        piVar1[2] = *(int *)(param_1 + 0x12);
        piVar1[3] = *(int *)(param_1 + 0x14);
        piVar1[4] = *(int *)(param_1 + 0x16);
        *(undefined *)(piVar1 + 5) = 1;
      }
      *(float *)(param_1 + 6) = (float)piVar1[2] * FLOAT_803db414 + *(float *)(param_1 + 6);
      *(float *)(param_1 + 8) = (float)piVar1[3] * FLOAT_803db414 + *(float *)(param_1 + 8);
      *(float *)(param_1 + 10) = (float)piVar1[4] * FLOAT_803db414 + *(float *)(param_1 + 10);
      local_20 = FLOAT_803e58dc;
      FUN_80098928((double)FLOAT_803e58e0,param_1,4,0x185,5,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0xa9,auStack40,1,0xffffffff,0);
      if (*(short *)(piVar1 + 1) < 0x10) {
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
      }
      else {
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6e) = 5;
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6f) = 1;
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x48) = 0x10;
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x4c) = 0x10;
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
      }
      *(ushort *)(piVar1 + 1) = *(short *)(piVar1 + 1) + (ushort)DAT_803db410;
    }
  }
  return;
}

