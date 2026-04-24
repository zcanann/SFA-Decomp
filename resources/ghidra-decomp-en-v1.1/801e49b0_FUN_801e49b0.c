// Function: FUN_801e49b0
// Entry: 801e49b0
// Size: 460 bytes

void FUN_801e49b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  int *piVar1;
  undefined auStack_28 [8];
  float local_20;
  
  piVar1 = *(int **)(param_9 + 0x5c);
  if (*piVar1 == 0) {
    *piVar1 = *(int *)(param_9 + 0x7c);
  }
  if (*piVar1 != 0) {
    *param_9 = 0;
    param_9[2] = param_9[2] + (ushort)DAT_803dc070 * -800;
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (*(int *)(param_9 + 0x7a) < 0) {
      FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else {
      if (*(char *)(piVar1 + 5) == '\0') {
        piVar1[2] = *(int *)(param_9 + 0x12);
        piVar1[3] = *(int *)(param_9 + 0x14);
        piVar1[4] = *(int *)(param_9 + 0x16);
        *(undefined *)(piVar1 + 5) = 1;
      }
      *(float *)(param_9 + 6) = (float)piVar1[2] * FLOAT_803dc074 + *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) = (float)piVar1[3] * FLOAT_803dc074 + *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) = (float)piVar1[4] * FLOAT_803dc074 + *(float *)(param_9 + 10);
      local_20 = FLOAT_803e6574;
      FUN_80098bb4((double)FLOAT_803e6578,param_9,4,0x185,5,0);
      (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,auStack_28,1,0xffffffff,0);
      if (*(short *)(piVar1 + 1) < 0x10) {
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      }
      else {
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
        *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
        *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
        *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
      }
      *(ushort *)(piVar1 + 1) = *(short *)(piVar1 + 1) + (ushort)DAT_803dc070;
    }
  }
  return;
}

