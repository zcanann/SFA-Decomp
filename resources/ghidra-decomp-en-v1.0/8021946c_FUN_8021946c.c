// Function: FUN_8021946c
// Entry: 8021946c
// Size: 212 bytes

void FUN_8021946c(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar2 = FUN_802860dc();
  iVar6 = *(int *)(iVar2 + 0xb8);
  FUN_8002b9ec();
  iVar5 = *(int *)(iVar2 + 0x4c);
  FUN_80035f20(iVar2);
  FUN_8003393c(iVar2);
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
    if ((*(char *)(param_3 + iVar4 + 0x81) == '\x01') && (*(char *)(iVar5 + 0x19) != '\0')) {
      FUN_8002ce88(iVar2);
      FUN_80035f00(iVar2);
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    }
  }
  iVar4 = (int)*(short *)(*(int *)(iVar6 + 0x6dc) + 4);
  uVar3 = FUN_80114bb0(iVar2,param_3,iVar6,iVar4,iVar4);
  uVar1 = countLeadingZeros(uVar3);
  uVar1 = countLeadingZeros(uVar1 >> 5);
  FUN_80286128(uVar1 >> 5);
  return;
}

