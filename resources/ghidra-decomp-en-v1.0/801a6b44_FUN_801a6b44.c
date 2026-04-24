// Function: FUN_801a6b44
// Entry: 801a6b44
// Size: 220 bytes

void FUN_801a6b44(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  uVar2 = FUN_8001ffb4(0xf33);
  *(undefined4 *)(param_1 + 0xf8) = uVar2;
  *(code **)(param_1 + 0xbc) = FUN_801a6638;
  uVar2 = FUN_800481b0(0x12);
  FUN_8004350c(uVar2,0,0);
  FLOAT_803ddb28 = FLOAT_803e44c8;
  DAT_803ddb2c = 0;
  FUN_8000a518(0xcc,0);
  FUN_8000a518(0xdb,0);
  FUN_8000a518(0xf2,0);
  FUN_8000a518(0xce,0);
  FUN_8000a518(0xc2,0);
  FUN_800200e8(0xdcf,0);
  return;
}

