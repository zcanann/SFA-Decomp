// Function: FUN_801c9604
// Entry: 801c9604
// Size: 164 bytes

void FUN_801c9604(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar2 = 0;
  }
  FUN_800146a8();
  FUN_8003709c(param_1,0xb);
  FUN_8000a538((int *)0xd8,0);
  FUN_8000a538((int *)0xd9,0);
  FUN_8000a538((int *)0x8,0);
  FUN_8000a538((int *)0xe,0);
  FUN_800201ac(0xefa,0);
  FUN_800201ac(0xcbb,1);
  return;
}

