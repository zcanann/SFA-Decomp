// Function: FUN_80157e34
// Entry: 80157e34
// Size: 208 bytes

void FUN_80157e34(undefined4 param_1)

{
  bool bVar1;
  byte bVar3;
  uint uVar2;
  byte bVar4;
  
  bVar3 = FUN_8014c594(param_1,0,0x28,&DAT_803ad108);
  bVar1 = true;
  if (bVar3 != 0) {
    for (bVar4 = 0; bVar4 < bVar3; bVar4 = bVar4 + 1) {
      if (((*(short *)((&DAT_803ad108)[(uint)bVar4 * 2] + 0x46) == 0x6a3) &&
          (uVar2 = *(uint *)(*(int *)((&DAT_803ad108)[(uint)bVar4 * 2] + 0xb8) + 0x2dc),
          (uVar2 & 0x20000000) != 0)) && ((uVar2 & 0x1800) == 0)) {
        bVar1 = false;
        bVar4 = bVar3;
      }
    }
  }
  if (bVar1) {
    (**(code **)(*DAT_803dd6d0 + 0x24))(0,0,0);
  }
  return;
}

