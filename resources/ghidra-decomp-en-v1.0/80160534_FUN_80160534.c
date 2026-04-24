// Function: FUN_80160534
// Entry: 80160534
// Size: 116 bytes

undefined4 FUN_80160534(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(byte *)(param_1 + 0x36) < DAT_803db410) {
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    *(byte *)(param_1 + 0x36) = *(byte *)(param_1 + 0x36) - DAT_803db410;
  }
  if (*(char *)(param_1 + 0x36) == '\0') {
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

