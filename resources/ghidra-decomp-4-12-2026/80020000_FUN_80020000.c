// Function: FUN_80020000
// Entry: 80020000
// Size: 120 bytes

uint FUN_80020000(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = FUN_80020078(param_1);
  uVar2 = uVar1 + 1;
  if ((int)uVar2 < 1 << (*(byte *)(DAT_803dd75c + param_1 * 4 + 2) & 0x1f) + 1) {
    FUN_800201ac(param_1,uVar2);
    uVar1 = uVar2;
  }
  return uVar1;
}

