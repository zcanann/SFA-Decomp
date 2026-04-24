// Function: FUN_80170f38
// Entry: 80170f38
// Size: 100 bytes

void FUN_80170f38(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar2 = 0;
  }
  FUN_8000b844(param_1,0x42c);
  FUN_8000b844(param_1,0x42d);
  return;
}

