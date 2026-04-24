// Function: FUN_802127d4
// Entry: 802127d4
// Size: 324 bytes

undefined4 FUN_802127d4(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (((*(ushort *)(DAT_803ddd54 + 0xfa) & 8) != 0) ||
       (fVar1 = *(float *)(DAT_803ddd54 + 4) - FLOAT_803db414, *(float *)(DAT_803ddd54 + 4) = fVar1,
       fVar1 <= FLOAT_803e67b8)) {
      if ((*(ushort *)(DAT_803ddd54 + 0xfa) & 8) != 0) {
        *(char *)(DAT_803ddd54 + 0x102) = *(char *)(DAT_803ddd54 + 0x102) + -1;
        *(undefined *)(param_2 + 0x354) = 3;
      }
      *(ushort *)(DAT_803ddd54 + 0xfa) = *(ushort *)(DAT_803ddd54 + 0xfa) & 0xffef;
      if (*(char *)(DAT_803ddd54 + 0x102) == '\0') {
        return 2;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      return 10;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,7);
    *(float *)(DAT_803ddd54 + 4) =
         (float)((double)CONCAT44(0x43300000,
                                  (uint)*(ushort *)
                                         (iVar2 + (*(byte *)(DAT_803ddd54 + 0x101) & 0xfffffffe) +
                                         0x4a)) - DOUBLE_803e67e0);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  return 0;
}

