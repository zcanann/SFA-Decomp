// Function: FUN_8020ad50
// Entry: 8020ad50
// Size: 120 bytes

void FUN_8020ad50(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x45);
  if (*(int *)(param_1 + 200) != 0) {
    FUN_80037cb0(param_1);
  }
  if (*(int *)(iVar1 + 0x160) != 0) {
    FUN_8001f384();
  }
  FUN_8000a518(0x26,0);
  FUN_8000a518(0x96,0);
  return;
}

