// Function: FUN_8015b614
// Entry: 8015b614
// Size: 92 bytes

undefined4 FUN_8015b614(int param_1,int param_2)

{
  int iVar1;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 0x405) = 0;
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f4),0);
    FUN_800200e8((int)*(short *)(iVar1 + 0x3f2),1);
  }
  return 0;
}

