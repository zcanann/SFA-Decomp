// Function: FUN_802150c0
// Entry: 802150c0
// Size: 340 bytes

undefined4 FUN_802150c0(uint param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  
  *(undefined *)(param_3 + 0x56) = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 4) {
      *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x1000;
    }
    else if (bVar1 < 4) {
      if (bVar1 == 2) {
        *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 8;
      }
      else if (bVar1 < 2) {
        if (bVar1 != 0) {
          *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 4;
        }
      }
      else {
        *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x800;
      }
    }
    else if (bVar1 == 6) {
      if (*(uint *)(DAT_803de9d4 + 0x178) != 0) {
        FUN_8001f448(*(uint *)(DAT_803de9d4 + 0x178));
        *(undefined4 *)(DAT_803de9d4 + 0x178) = 0;
      }
    }
    else if (bVar1 < 6) {
      *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x20000;
    }
  }
  FUN_80214814(param_1);
  if (*(int *)(param_1 + 0xf8) == 0) {
    *(undefined4 *)(param_1 + 0xf8) = 1;
  }
  else if (*(int *)(param_1 + 0xf8) == 3) {
    *(undefined4 *)(param_1 + 0xf8) = 4;
  }
  return 0;
}

