// Function: FUN_80041018
// Entry: 80041018
// Size: 236 bytes

void FUN_80041018(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar1 = FUN_802860d4();
  iVar5 = *(int *)(*(int *)(iVar1 + 0x50) + 0x40);
  iVar6 = *(int *)(iVar1 + 0x74);
  if ((*(byte *)(iVar1 + 0xaf) & 0x28) == 0) {
    uVar2 = FUN_8002b588();
    iVar7 = iVar5;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(*(int *)(iVar1 + 0x50) + 0x72); iVar4 = iVar4 + 1)
    {
      if (*(char *)(iVar7 + *(char *)(iVar1 + 0xad) + 0x12) < '\0') {
        uVar3 = 0;
      }
      else {
        uVar3 = FUN_8002856c(uVar2);
      }
      FUN_80041104(0,iVar6 + 0xc,iVar7 + 6,*(byte *)(iVar5 + 0x10) & 0x10,iVar1,0);
      FUN_80041104(uVar3,iVar6,iVar7,*(byte *)(iVar5 + 0x10) & 0x10,iVar1,1);
      iVar7 = iVar7 + 0x18;
      iVar6 = iVar6 + 0x18;
    }
  }
  FUN_80286120();
  return;
}

