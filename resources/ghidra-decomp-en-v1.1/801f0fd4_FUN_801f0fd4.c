// Function: FUN_801f0fd4
// Entry: 801f0fd4
// Size: 164 bytes

void FUN_801f0fd4(int param_1)

{
  uint uVar1;
  
  if ((((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(short *)(*(int *)(param_1 + 0xb8) + 6) == 2)) &&
     (uVar1 = FUN_80020078(0x9ad), uVar1 == 0)) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
    FUN_80014b68(0,0x100);
    FUN_800201ac(0x9ad,1);
  }
  FUN_8002fb40((double)FLOAT_803e699c,(double)FLOAT_803dc074);
  return;
}

