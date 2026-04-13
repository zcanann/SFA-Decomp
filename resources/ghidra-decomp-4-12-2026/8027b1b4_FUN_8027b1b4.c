// Function: FUN_8027b1b4
// Entry: 8027b1b4
// Size: 68 bytes

/* WARNING: Removing unreachable block (ram,0x8027b1d4) */

undefined4 FUN_8027b1b4(byte *param_1)

{
  undefined4 uVar1;
  
  if (*param_1 < 2) {
    uVar1 = FUN_8027b060((char *)param_1,*(uint *)(param_1 + 0x20));
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

