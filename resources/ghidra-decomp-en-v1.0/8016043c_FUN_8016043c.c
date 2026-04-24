// Function: FUN_8016043c
// Entry: 8016043c
// Size: 208 bytes

undefined4 FUN_8016043c(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    uVar1 = FUN_8002b9ec();
    FUN_800378c4(uVar1,0xe0000,param_1,0);
    if (*(int *)(param_1 + 0x4c) == 0) {
      FUN_8002cbc4(param_1);
      uVar1 = 0;
    }
    else {
      uVar1 = 4;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,3);
    *(undefined4 *)(param_2 + 0x2d0) = 0;
    *(undefined *)(param_2 + 0x25f) = 0;
    *(undefined *)(param_2 + 0x349) = 0;
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    uVar1 = 0;
  }
  return uVar1;
}

