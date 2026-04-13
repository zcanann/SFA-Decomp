// Function: FUN_800ea3f8
// Entry: 800ea3f8
// Size: 140 bytes

void FUN_800ea3f8(int param_1)

{
  undefined *puVar1;
  uint uVar2;
  short sVar3;
  
  puVar1 = FUN_800e82c8();
  for (sVar3 = 0; sVar3 < 0xd; sVar3 = sVar3 + 1) {
    uVar2 = FUN_80020078((int)sVar3 + 0xf10);
    *(char *)(param_1 + sVar3) = (char)uVar2;
  }
  *(undefined *)(param_1 + *(short *)(&DAT_80312630 + (uint)(byte)puVar1[5] * 2)) = 1;
  return;
}

