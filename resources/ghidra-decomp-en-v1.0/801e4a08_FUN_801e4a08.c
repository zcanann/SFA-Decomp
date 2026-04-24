// Function: FUN_801e4a08
// Entry: 801e4a08
// Size: 176 bytes

void FUN_801e4a08(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) = *(ushort *)(*(int *)(param_1 + 0x54) + 0xb2) | 1;
  if (*(int *)(iVar2 + 0x18) == 0) {
    uVar1 = FUN_8001f4c8(param_1,1);
    *(undefined4 *)(iVar2 + 0x18) = uVar1;
    if (*(int *)(iVar2 + 0x18) != 0) {
      FUN_8001db2c(*(int *)(iVar2 + 0x18),2);
      FUN_8001daf0(*(undefined4 *)(iVar2 + 0x18),0,0x5a,0x96,0);
      FUN_8001db14(*(undefined4 *)(iVar2 + 0x18),1);
      FUN_8001dc38((double)FLOAT_803e5910,(double)FLOAT_803e5914,*(undefined4 *)(iVar2 + 0x18));
    }
  }
  return;
}

