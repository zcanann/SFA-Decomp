// Function: FUN_80189af8
// Entry: 80189af8
// Size: 112 bytes

void FUN_80189af8(int param_1,int param_2)

{
  uint uVar1;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(undefined *)(*(int *)(param_1 + 0xb8) + 0x16) = 1;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  if (uVar1 == 0) {
    FUN_80043604(0,0,1);
  }
  *(code **)(param_1 + 0xbc) = FUN_80189218;
  return;
}

