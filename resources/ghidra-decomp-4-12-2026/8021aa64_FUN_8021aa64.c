// Function: FUN_8021aa64
// Entry: 8021aa64
// Size: 104 bytes

void FUN_8021aa64(int param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_8021a7e4;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    *(byte *)(puVar2 + 1) = *(byte *)(puVar2 + 1) & 0xdf | 0x20;
    *puVar2 = 2;
  }
  return;
}

