// Function: FUN_8018053c
// Entry: 8018053c
// Size: 140 bytes

void FUN_8018053c(int param_1)

{
  int iVar1;
  int iVar2;
  undefined auStack96 [88];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_800640cc((double)FLOAT_803e38b4,param_1 + 0x80,param_1 + 0xc,2,auStack96,param_1,8,
                       0xffffffff,0xff,0);
  if (iVar1 != 0) {
    *(undefined *)(iVar2 + 0x1a) = 1;
  }
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  return;
}

