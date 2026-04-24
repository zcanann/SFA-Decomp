// Function: FUN_80027104
// Entry: 80027104
// Size: 184 bytes

void FUN_80027104(int *param_1,undefined4 param_2)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *param_1;
  for (uVar3 = 0; uVar3 < *(byte *)(iVar4 + 0xf3); uVar3 = uVar3 + 1) {
    uVar2 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar2 == 0) {
      iVar1 = 1;
    }
    else {
      iVar1 = uVar2 + *(byte *)(*param_1 + 0xf4);
    }
    uVar2 = uVar3;
    if (iVar1 <= (int)uVar3) {
      uVar2 = 0;
    }
    iVar1 = param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + uVar2 * 0x40;
    FUN_80246eb4(param_2,iVar1,iVar1);
  }
  return;
}

