// Function: FUN_802b8a68
// Entry: 802b8a68
// Size: 160 bytes

void FUN_802b8a68(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  uVar4 = *(undefined4 *)(iVar2 + 0xb8);
  FUN_80036fa4(iVar2,3);
  bVar1 = *(byte *)(iVar2 + 0xeb);
  for (iVar3 = 0; iVar3 < (int)(uint)bVar1; iVar3 = iVar3 + 1) {
    iVar5 = *(int *)(iVar2 + 200);
    if ((iVar5 != 0) && (FUN_80037cb0(iVar2,iVar5), (int)uVar6 == 0)) {
      FUN_8002cbc4(iVar5);
    }
  }
  (**(code **)(*DAT_803dcab8 + 0x40))(iVar2,uVar4,0x20);
  FUN_80286124();
  return;
}

