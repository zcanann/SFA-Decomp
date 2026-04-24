// Function: FUN_8005cf8c
// Entry: 8005cf8c
// Size: 304 bytes

void FUN_8005cf8c(int param_1,int param_2,int param_3)

{
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  FUN_802573f8();
  FUN_80256978(0,1);
  FUN_80256978(9,1);
  FUN_80256978(0xb,1);
  FUN_80256978(0xd,1);
  FUN_8025889c(0x90,0,param_3 * 3 & 0xffff);
  for (iVar4 = 0; iVar4 < param_3; iVar4 = iVar4 + 1) {
    iVar5 = 0;
    iVar6 = 3;
    do {
      write_volatile_1(DAT_cc008000,0);
      iVar2 = iVar5 + 1;
      puVar1 = (undefined2 *)(param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10);
      write_volatile_2(0xcc008000,*puVar1);
      write_volatile_2(0xcc008000,puVar1[1]);
      write_volatile_2(0xcc008000,puVar1[2]);
      iVar3 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      write_volatile_1(DAT_cc008000,*(undefined *)(iVar3 + 0xc));
      write_volatile_1(DAT_cc008000,*(undefined *)(iVar3 + 0xd));
      write_volatile_1(DAT_cc008000,*(undefined *)(iVar3 + 0xe));
      write_volatile_1(DAT_cc008000,*(undefined *)(iVar3 + 0xf));
      iVar2 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      write_volatile_2(0xcc008000,*(undefined2 *)(iVar2 + 8));
      write_volatile_2(0xcc008000,*(undefined2 *)(iVar2 + 10));
      iVar5 = iVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    param_2 = param_2 + 0x10;
  }
  return;
}

