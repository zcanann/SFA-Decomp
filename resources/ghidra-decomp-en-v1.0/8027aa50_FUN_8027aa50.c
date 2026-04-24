// Function: FUN_8027aa50
// Entry: 8027aa50
// Size: 68 bytes

/* WARNING: Removing unreachable block (ram,0x8027aa70) */

undefined4 FUN_8027aa50(byte *param_1)

{
  undefined4 uVar1;
  
  if (*param_1 < 2) {
    uVar1 = FUN_8027a8fc(param_1,*(undefined4 *)(param_1 + 0x20));
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

