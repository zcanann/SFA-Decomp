// Function: FUN_802654dc
// Entry: 802654dc
// Size: 264 bytes

void FUN_802654dc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  ushort uVar1;
  ushort uVar2;
  
  *(undefined4 *)(DAT_803de210 + 0x6b0) = param_1;
  *(undefined4 *)(DAT_803de210 + 0x6b4) = param_2;
  *(undefined4 *)(DAT_803de210 + 0x6b8) = param_3;
  uVar2 = *(ushort *)(DAT_803de210 + 0x698);
  uVar1 = *(ushort *)(DAT_803de210 + 0x694);
  DAT_803de204 = 0x70007;
  DAT_803de208 = 0x3d043d04;
  FUN_80265290(0x3d043d04);
  if ((*(short *)(DAT_803de210 + 0x692) == 0x200) && (uVar1 == 0x1c0)) {
    for (; uVar2 < 0x1c0; uVar2 = uVar2 + 0x10) {
      FUN_802655e8();
    }
  }
  else if ((*(short *)(DAT_803de210 + 0x692) == 0x280) && (uVar1 == 0x1e0)) {
    for (; uVar2 < 0x1e0; uVar2 = uVar2 + 0x10) {
      FUN_80267070();
    }
  }
  else {
    for (; uVar2 < uVar1; uVar2 = uVar2 + 0x10) {
      FUN_80268afc();
    }
  }
  return;
}

