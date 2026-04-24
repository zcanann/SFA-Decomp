// Function: FUN_8022b8a0
// Entry: 8022b8a0
// Size: 244 bytes

void FUN_8022b8a0(undefined4 param_1,int param_2)

{
  float fVar1;
  
  fVar1 = FLOAT_803e6ecc;
  if (*(int *)(param_2 + 0x438) == 0) {
    if (FLOAT_803e6ecc < *(float *)(param_2 + 0x440)) {
      *(float *)(param_2 + 0x440) = *(float *)(param_2 + 0x440) - FLOAT_803db414;
      if (fVar1 <= *(float *)(param_2 + 0x440)) {
        return;
      }
      *(float *)(param_2 + 0x440) = fVar1;
    }
    if ((*(ushort *)(param_2 + 0x3f4) & 0x200) != 0) {
      if (*(char *)(param_2 + 0x43c) == '\x01') {
        FUN_8022b764(param_1,param_2,0);
        FUN_8022b764(param_1,param_2,1);
      }
      else {
        FUN_8022b764(param_1,param_2,*(undefined *)(param_2 + 0x43d));
        *(byte *)(param_2 + 0x43d) = *(byte *)(param_2 + 0x43d) ^ 1;
      }
      *(float *)(param_2 + 0x440) =
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x444)) - DOUBLE_803e6ee8
                  );
    }
  }
  return;
}

