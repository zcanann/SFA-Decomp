// Function: FUN_802375c4
// Entry: 802375c4
// Size: 504 bytes

void FUN_802375c4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((*(short *)(iVar2 + 0x24) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    if (*(short *)(param_1 + 0x46) == 0x807) {
      if ((*(char *)(iVar2 + 0x1b) != '\0') && (*(char *)(iVar2 + 0x1c) != '\0')) {
        FUN_800971a0((double)*(float *)(iVar2 + 0x20),param_1,*(char *)(iVar2 + 0x1b),
                     *(char *)(iVar2 + 0x1c),*(undefined *)(iVar2 + 0x1d),0);
      }
    }
    else if (*(short *)(param_1 + 0x46) == 0x80e) {
      if ((*(char *)(iVar2 + 0x1b) != '\0') && (*(char *)(iVar2 + 0x1c) != '\0')) {
        FUN_80097070((double)*(float *)(iVar2 + 0x20),param_1,*(char *)(iVar2 + 0x1b),
                     *(char *)(iVar2 + 0x1c),*(undefined *)(iVar2 + 0x1d),0);
      }
    }
    else if (((*(char *)(iVar2 + 0x1b) != '\0') && (*(char *)(iVar2 + 0x1c) != '\0')) &&
            (*(char *)(iVar2 + 0x1d) != '\0')) {
      if (*(char *)(iVar2 + 0x2a) == '\0') {
        FUN_80097b30((double)*(float *)(iVar2 + 0x20),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x26)) -
                                    DOUBLE_803e73c8),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x27)) -
                                    DOUBLE_803e73c8),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x28)) -
                                    DOUBLE_803e73c8),param_1);
      }
      else if (*(char *)(iVar2 + 0x2a) == '\x01') {
        FUN_80097734((double)*(float *)(iVar2 + 0x20),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x26)) -
                                    DOUBLE_803e73c8),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x27)) -
                                    DOUBLE_803e73c8),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x28)) -
                                    DOUBLE_803e73c8),param_1);
      }
      else {
        FUN_800972dc((double)*(float *)(iVar2 + 0x20),
                     (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x26)) -
                                    DOUBLE_803e73c8),param_1);
      }
    }
  }
  return;
}

