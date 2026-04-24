// Function: FUN_801a01e8
// Entry: 801a01e8
// Size: 296 bytes

void FUN_801a01e8(int param_1)

{
  int iVar1;
  int iVar2;
  int local_70;
  undefined4 local_6c;
  float local_68;
  undefined4 local_64;
  undefined auStack96 [88];
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0x7f;
  if (*(int *)(param_1 + 0xc4) != 0) {
    iVar1 = FUN_8003687c(param_1,&local_70,0,0);
    if ((iVar1 == 0) && (local_70 = *(int *)(*(int *)(param_1 + 0x54) + 0x50), local_70 == 0)) {
      return;
    }
    iVar1 = FUN_8002b9ec();
    if ((local_70 == iVar1) && (iVar1 = FUN_80295cd4(local_70), iVar1 == 0)) {
      local_6c = *(undefined4 *)(local_70 + 0xc);
      local_68 = FLOAT_803e4298 + *(float *)(local_70 + 0x10);
      local_64 = *(undefined4 *)(local_70 + 0x14);
      iVar1 = FUN_80221d6c(param_1 + 0xc,&local_6c);
      if (iVar1 != 0) {
        if ((*(int *)(param_1 + 0xf4) == 0) &&
           (iVar1 = FUN_800640cc((double)FLOAT_803e429c,param_1 + 0xc,&local_6c,0,auStack96,param_1,
                                 4,0xffffffff,0,0), iVar1 != 0)) {
          return;
        }
        *(byte *)(iVar2 + 8) = *(byte *)(iVar2 + 8) & 0x7f | 0x80;
      }
    }
  }
  return;
}

