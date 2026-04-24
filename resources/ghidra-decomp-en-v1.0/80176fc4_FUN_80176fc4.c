// Function: FUN_80176fc4
// Entry: 80176fc4
// Size: 108 bytes

undefined4 FUN_80176fc4(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if (((*(char *)(*(int *)(param_1 + 0x4c) + 0x1d) != '\x02') &&
      (*(char *)(param_3 + 0x80) == '\x01')) &&
     (iVar1 = (int)*(char *)(*(int *)(param_1 + 0x4c) + 0x1a), -1 < iVar1)) {
    FUN_800552e8(iVar1,1);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  return 0;
}

