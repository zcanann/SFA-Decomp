// Function: FUN_801ce344
// Entry: 801ce344
// Size: 192 bytes

void FUN_801ce344(uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_80020078(10);
  if (uVar1 == 0) {
    FUN_8000dcdc(param_1,0x372);
    FUN_8000dcdc(param_1,0x373);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    FUN_80036018(param_1);
  }
  else {
    *(undefined2 *)(param_1 + 6) = 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_8000dbb0();
    FUN_8000dbb0();
    FUN_80035ff8(param_1);
    FUN_800201ac(0x398,1);
  }
  return;
}

