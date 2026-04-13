// Function: FUN_80187044
// Entry: 80187044
// Size: 168 bytes

void FUN_80187044(int param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
    *puVar1 = 0;
  }
  if (((param_2 == 0) && (*puVar1 != 0)) && (*(byte *)(puVar1 + 0x1c) >> 6 != 1)) {
    DAT_803de758 = 0;
  }
  FUN_8003709c(param_1,0x30);
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

