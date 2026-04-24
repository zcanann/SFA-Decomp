// Function: FUN_800ea174
// Entry: 800ea174
// Size: 140 bytes

void FUN_800ea174(int param_1)

{
  int iVar1;
  undefined uVar2;
  short sVar3;
  
  iVar1 = FUN_800e8044();
  for (sVar3 = 0; sVar3 < 0xd; sVar3 = sVar3 + 1) {
    uVar2 = FUN_8001ffb4(sVar3 + 0xf10);
    *(undefined *)(param_1 + sVar3) = uVar2;
  }
  *(undefined *)(param_1 + *(short *)(&DAT_803119e0 + (uint)*(byte *)(iVar1 + 5) * 2)) = 1;
  return;
}

