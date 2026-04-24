// Function: FUN_80167988
// Entry: 80167988
// Size: 216 bytes

undefined4 FUN_80167988(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      if (*(int *)(param_1 + 0x4c) == 0) {
        FUN_8002cbc4();
        return 0;
      }
      return 4;
    }
  }
  else {
    *(undefined *)(*(int *)(iVar1 + 0x40c) + 0x4b) = 0;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,7);
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    *(ushort *)(iVar1 + 0x400) = *(ushort *)(iVar1 + 0x400) | 0x20;
    *(float *)(iVar1 + 1000) = FLOAT_803e3078;
    *(float *)(iVar1 + 0x3ec) = FLOAT_803e307c;
  }
  return 0;
}

