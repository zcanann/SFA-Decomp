// Function: FUN_801d0338
// Entry: 801d0338
// Size: 348 bytes

undefined4 FUN_801d0338(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = FUN_8002e1ac(*(int *)(&DAT_80327638 + (uint)*(byte *)(param_1 + 0xe) * 4));
  iVar2 = FUN_8003809c(iVar1,0x1ee);
  if (iVar2 == 0) {
    if (*(byte *)(param_1 + 0xe) != 0) {
      iVar1 = FUN_8002e1ac((int)(&PTR_LAB_80327634)[*(byte *)(param_1 + 0xe)]);
      iVar2 = FUN_8003809c(iVar1,0x1ee);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
        *(undefined *)(param_1 + 4) = 9;
        *(char *)(param_1 + 0xc) =
             (char)*(undefined4 *)(&DAT_80327650 + (uint)*(byte *)(param_1 + 0xe) * 4);
        *(undefined *)(param_1 + 5) = 0;
        return 2;
      }
    }
    uVar3 = 0;
  }
  else {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,iVar1,0xffffffff);
    *(undefined *)(param_1 + 4) = 9;
    *(char *)(param_1 + 0xc) =
         (char)*(undefined4 *)(&DAT_80327654 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xd) =
         (char)*(undefined4 *)(&DAT_80327670 + (uint)*(byte *)(param_1 + 0xe) * 4);
    *(char *)(param_1 + 0xe) = *(char *)(param_1 + 0xe) + '\x01';
    *(undefined *)(param_1 + 5) = 0x1e;
    uVar3 = 1;
  }
  return uVar3;
}

