// Function: FUN_801b3768
// Entry: 801b3768
// Size: 104 bytes

undefined4 FUN_801b3768(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x4c);
  *(undefined *)(param_3 + 0x56) = 0;
  if (((*(byte *)(iVar1 + 0x1d) & 2) != 0) && (*(char *)(param_3 + 0x80) == '\x01')) {
    FUN_800200e8((int)*(short *)(iVar1 + 0x18),1);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  return 0;
}

