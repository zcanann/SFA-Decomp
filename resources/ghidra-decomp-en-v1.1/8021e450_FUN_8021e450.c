// Function: FUN_8021e450
// Entry: 8021e450
// Size: 228 bytes

undefined4 FUN_8021e450(int param_1,undefined param_2)

{
  switch(param_2) {
  case 5:
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,*(undefined4 *)(param_1 + 0xb8),8);
    break;
  case 6:
    FUN_800201ac(0x634,1);
    (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
    break;
  case 8:
    (**(code **)(*DAT_803dd6d4 + 0x48))(7,param_1,0xffffffff);
    break;
  case 9:
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,*(undefined4 *)(param_1 + 0xb8),7);
  }
  return 0;
}

