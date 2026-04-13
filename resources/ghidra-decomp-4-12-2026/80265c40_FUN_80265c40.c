// Function: FUN_80265c40
// Entry: 80265c40
// Size: 264 bytes

void FUN_80265c40(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  ushort uVar1;
  ushort uVar2;
  
  *(undefined4 *)(DAT_803dee90 + 0x6b0) = param_1;
  *(undefined4 *)(DAT_803dee90 + 0x6b4) = param_2;
  *(undefined4 *)(DAT_803dee90 + 0x6b8) = param_3;
  uVar2 = *(ushort *)(DAT_803dee90 + 0x698);
  uVar1 = *(ushort *)(DAT_803dee90 + 0x694);
  DAT_803dee84 = 0x70007;
  DAT_803dee88 = 0x3d043d04;
  FUN_802659f4();
  if ((*(short *)(DAT_803dee90 + 0x692) == 0x200) && (uVar1 == 0x1c0)) {
    for (; uVar2 < 0x1c0; uVar2 = uVar2 + 0x10) {
      FUN_80265d4c();
    }
  }
  else if ((*(short *)(DAT_803dee90 + 0x692) == 0x280) && (uVar1 == 0x1e0)) {
    for (; uVar2 < 0x1e0; uVar2 = uVar2 + 0x10) {
      FUN_802677d4();
    }
  }
  else {
    for (; uVar2 < uVar1; uVar2 = uVar2 + 0x10) {
      FUN_80269260();
    }
  }
  return;
}

