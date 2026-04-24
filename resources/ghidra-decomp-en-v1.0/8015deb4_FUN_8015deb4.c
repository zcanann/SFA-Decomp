// Function: FUN_8015deb4
// Entry: 8015deb4
// Size: 108 bytes

undefined4 FUN_8015deb4(int param_1,int param_2)

{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    if (*(short *)(iVar1 + 0x3f4) != -1) {
      FUN_800200e8((int)*(short *)(iVar1 + 0x3f4),0);
    }
    if (*(short *)(iVar1 + 0x3f2) != -1) {
      FUN_800200e8((int)*(short *)(iVar1 + 0x3f2),1);
    }
  }
  return 0;
}

