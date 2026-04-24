// Function: FUN_8017f918
// Entry: 8017f918
// Size: 124 bytes

void FUN_8017f918(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x34);
  FUN_80036fa4(param_1,0x3e);
  if ((*(char *)(param_1 + 0xeb) != '\0') && (FUN_80037cb0(param_1,*puVar1), param_2 == 0)) {
    FUN_8002cbc4(*puVar1);
  }
  return;
}

