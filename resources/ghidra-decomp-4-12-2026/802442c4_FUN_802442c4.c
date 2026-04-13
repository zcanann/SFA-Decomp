// Function: FUN_802442c4
// Entry: 802442c4
// Size: 136 bytes

uint FUN_802442c4(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  FUN_80243e74();
  uVar1 = DAT_800000c4;
  uVar2 = DAT_800000c4 | DAT_800000c8;
  DAT_800000c4 = DAT_800000c4 & ~param_1;
  uVar3 = DAT_800000c4 | DAT_800000c8;
  for (uVar2 = param_1 & uVar2; uVar2 != 0; uVar2 = FUN_80243f64(uVar2,uVar3)) {
  }
  FUN_80243e9c();
  return uVar1;
}

