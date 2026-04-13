// Function: FUN_801c3388
// Entry: 801c3388
// Size: 148 bytes

void FUN_801c3388(int param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  puVar3 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar3;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar3 = 0;
  }
  FUN_800146a8();
  iVar2 = FUN_8004832c(0x1f);
  FUN_80043604(iVar2,1,0);
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_800201ac(0xefa,0);
  FUN_800201ac(0xcbb,1);
  return;
}

