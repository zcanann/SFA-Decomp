// Function: FUN_80246298
// Entry: 80246298
// Size: 112 bytes

undefined8 FUN_80246298(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_1 + 8);
  uVar2 = *(uint *)(param_1 + 0xc);
  if (*(int *)(param_1 + 0x30) != 0) {
    uVar5 = FUN_802473b4();
    uVar1 = (uint)uVar5 - *(uint *)(param_1 + 0x2c);
    bVar4 = CARRY4(uVar2,uVar1);
    uVar2 = uVar2 + uVar1;
    iVar3 = iVar3 + ((int)((ulonglong)uVar5 >> 0x20) -
                    ((uint)((uint)uVar5 < *(uint *)(param_1 + 0x2c)) + *(int *)(param_1 + 0x28))) +
                    (uint)bVar4;
  }
  return CONCAT44(iVar3,uVar2);
}

