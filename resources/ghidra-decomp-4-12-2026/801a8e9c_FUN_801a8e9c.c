// Function: FUN_801a8e9c
// Entry: 801a8e9c
// Size: 336 bytes

void FUN_801a8e9c(int param_1,int param_2)

{
  char cVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(undefined2 *)(iVar4 + 0x24) = 0;
  uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x1a));
  *(char *)(iVar4 + 0x2e) = (char)uVar3;
  cVar1 = *(char *)(iVar4 + 0x2e);
  if (cVar1 == '\0') {
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,1);
  }
  else {
    if (((byte)(cVar1 - 3U) < 2) || (cVar1 == '\x06')) {
      *(ushort *)(iVar4 + 0x24) = *(ushort *)(iVar4 + 0x24) | 0x400;
    }
    (**(code **)(*DAT_803dd740 + 0x20))(iVar4,0);
  }
  uVar2 = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0xc) = uVar2;
  *(undefined4 *)(iVar4 + 0x10) = uVar2;
  (**(code **)(*DAT_803dd740 + 4))(param_1,*(undefined4 *)(param_1 + 0xb8),0x32);
  (**(code **)(*DAT_803dd740 + 0x2c))(iVar4,1);
  FUN_800372f8(param_1,4);
  *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(param_1 + 0x14);
  FUN_80035ff8(param_1);
  FUN_801a8328(param_1,1,2);
  return;
}

