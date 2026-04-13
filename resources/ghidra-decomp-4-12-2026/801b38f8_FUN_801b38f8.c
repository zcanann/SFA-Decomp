// Function: FUN_801b38f8
// Entry: 801b38f8
// Size: 276 bytes

void FUN_801b38f8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  for (iVar5 = 0; iVar5 < (int)(uint)*(ushort *)(iVar1 + 0x9a); iVar5 = iVar5 + 1) {
    iVar3 = FUN_80060868(iVar1,iVar5);
    uVar2 = FUN_800607f4(iVar3);
    if (param_3 == uVar2) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 2;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) | 1;
      }
      else {
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffd;
        *(uint *)(iVar3 + 0x10) = *(uint *)(iVar3 + 0x10) & 0xfffffffe;
      }
    }
  }
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar5 = iVar5 + 1) {
    iVar3 = FUN_80060888(iVar1,iVar5);
    iVar4 = FUN_8004c3cc(iVar3,0);
    if (param_3 == *(byte *)(iVar4 + 5)) {
      if ((int)uVar6 == 0) {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) | 2;
      }
      else {
        *(uint *)(iVar3 + 0x3c) = *(uint *)(iVar3 + 0x3c) & 0xfffffffd;
      }
    }
  }
  FUN_80286888();
  return;
}

