// Function: FUN_80209778
// Entry: 80209778
// Size: 144 bytes

void FUN_80209778(int param_1)

{
  *(code **)(param_1 + 0xbc) = FUN_8020930c;
  FUN_8004350c(0,0,1);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  FUN_800887f8(0);
  FUN_800200e8(0x90d,1);
  FUN_800200e8(0x90e,1);
  FUN_800200e8(0x90f,1);
  FUN_8000a380(3,2,0x2ee);
  return;
}

