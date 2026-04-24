// Function: FUN_801609e0
// Entry: 801609e0
// Size: 116 bytes

undefined4 FUN_801609e0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(param_1 + 0x36) < DAT_803dc070) {
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    *(byte *)(param_1 + 0x36) = *(byte *)(param_1 + 0x36) - DAT_803dc070;
  }
  if (*(char *)(param_1 + 0x36) == '\0') {
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800201ac((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

