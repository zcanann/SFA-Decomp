// Function: FUN_80209db0
// Entry: 80209db0
// Size: 144 bytes

void FUN_80209db0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  *(code **)(param_9 + 0xbc) = FUN_80209944;
  FUN_80043604(0,0,1);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x2000;
  FUN_80088a84(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  FUN_800201ac(0x90d,1);
  FUN_800201ac(0x90e,1);
  FUN_800201ac(0x90f,1);
  FUN_8000a3a0(3,2,0x2ee);
  return;
}

