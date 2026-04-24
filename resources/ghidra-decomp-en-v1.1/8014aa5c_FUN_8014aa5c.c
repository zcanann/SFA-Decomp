// Function: FUN_8014aa5c
// Entry: 8014aa5c
// Size: 624 bytes

void FUN_8014aa5c(int param_1,int param_2)

{
  float local_28;
  float local_24;
  float afStack_20 [6];
  
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
    FUN_8014accc(param_1,param_2,&local_24,&local_28);
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000000) == 0) {
      if ((*(uint *)(param_2 + 0x2e4) & 0x20000000) == 0) {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e3250 < local_24) && (local_24 < FLOAT_803e3234)) {
          *(float *)(param_1 + 0x28) = local_24 * FLOAT_803dc078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
        }
      }
      else {
        local_24 = local_24 - *(float *)(param_1 + 0x10);
        if ((FLOAT_803e3250 < local_24) && (local_24 < FLOAT_803e3234)) {
          *(float *)(param_1 + 0x28) = (FLOAT_803e3254 + local_24) * FLOAT_803dc078;
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x8000000;
        }
      }
    }
    else {
      *(float *)(param_1 + 0x28) = (local_28 - *(float *)(param_1 + 0x10)) * FLOAT_803dc078;
    }
    if ((*(uint *)(param_2 + 0x2e4) & 8) == 0) {
      *(undefined *)(param_2 + 0x25f) = 0;
    }
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,param_2 + 4);
  if ((*(uint *)(param_2 + 0x2e4) & 4) != 0) {
    (**(code **)(*DAT_803dd728 + 0x14))(param_1,param_2 + 4);
  }
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,param_2 + 4);
  if (((*(char *)(param_2 + 0x25f) != '\0') && ((*(uint *)(param_2 + 0x2e4) & 0x28000002) == 0)) &&
     ((*(byte *)(param_2 + 0x264) & 0x10) != 0)) {
    *(float *)(param_1 + 0x28) = FLOAT_803e31fc;
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x100000;
  }
  if ((*(uint *)(param_2 + 0x2e4) & 0x200000) != 0) {
    FUN_80038378(param_1,2,2,afStack_20);
    FUN_8006ef48((double)*(float *)(param_2 + 0x310),(double)FLOAT_803e3200,param_1,
                 (uint)*(ushort *)(param_2 + 0x2f8),7,(int)afStack_20,param_2 + 4);
  }
  return;
}

