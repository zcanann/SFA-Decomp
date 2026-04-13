// Function: FUN_801d0d90
// Entry: 801d0d90
// Size: 136 bytes

void FUN_801d0d90(int param_1)

{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  uVar1 = FUN_80020078(0xbf);
  if (uVar1 == 0) {
    *puVar2 = 0;
  }
  else {
    uVar1 = FUN_80020078(0x4e4);
    if (uVar1 == 0) {
      FUN_800201ac(0xbf,0);
    }
    else {
      *puVar2 = 4;
    }
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

