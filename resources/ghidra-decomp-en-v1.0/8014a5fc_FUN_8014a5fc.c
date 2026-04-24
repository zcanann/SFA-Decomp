// Function: FUN_8014a5fc
// Entry: 8014a5fc
// Size: 624 bytes

void FUN_8014a5fc(int param_1,int param_2)

{
  float local_28;
  float local_24;
  undefined auStack32 [24];
  
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xf7efffff;
  if ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0xc) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
    else {
      *(undefined *)(param_2 + 0x25f) = 1;
    }
  }
  else {
    FUN_8014a86c(param_1,param_2,&local_24,&local_28);
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000000) == 0) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x20000000) == 0) {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e25bc < local_24) && (local_24 < FLOAT_803e25a0)) {
          *(float *)(param_1 + 0x28) = local_24 * FLOAT_803db418;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
        }
      }
      else {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e25bc < local_24) && (local_24 < FLOAT_803e25a0)) {
          *(float *)(param_1 + 0x28) = (FLOAT_803e25c0 + local_24) * FLOAT_803db418;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x8000000;
        }
      }
    }
    else {
      *(float *)(param_1 + 0x28) = (local_28 - *(float *)(param_1 + 0x10)) * FLOAT_803db418;
    }
    if ((*(uint *)(param_2 + 0x2e4) & 8) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
  }
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,param_2 + 4);
  if ((*(uint *)(param_2 + 0x2e4) & 4) != 0) {
    (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,param_2 + 4);
  }
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,param_2 + 4);
  if (((*(char *)(param_2 + 0x25f) != '\0') && ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0)) &&
     ((*(byte *)(param_2 + 0x264) & 0x10) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e2574;
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
  }
  if ((*(uint *)(param_2 + 0x2e4) & 0x200000) != 0) {
    FUN_80038280(param_1,2,2,auStack32);
    FUN_8006edcc((double)*(float *)(param_2 + 0x310),(double)FLOAT_803e256c,param_1,
                 *(undefined2 *)(param_2 + 0x2f8),7,auStack32,param_2 + 4);
  }
  return;
}

