// Function: FUN_802873f0
// Entry: 802873f0
// Size: 104 bytes

int FUN_802873f0(int param_1,undefined *param_2,int param_3)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = 0;
  for (iVar4 = 0; (iVar2 == 0 && (iVar4 < param_3)); iVar4 = iVar4 + 1) {
    uVar3 = *(uint *)(param_1 + 0xc);
    uVar1 = *param_2;
    if (uVar3 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar3 + 1;
      iVar2 = 0;
      *(undefined *)(param_1 + uVar3 + 0x10) = uVar1;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    else {
      iVar2 = 0x301;
    }
    param_2 = param_2 + 1;
  }
  return iVar2;
}

