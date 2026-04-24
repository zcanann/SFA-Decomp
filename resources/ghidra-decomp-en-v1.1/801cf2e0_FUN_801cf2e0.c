// Function: FUN_801cf2e0
// Entry: 801cf2e0
// Size: 224 bytes

void FUN_801cf2e0(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 5) {
    *(undefined **)(param_2 + 0x48) = &DAT_803dcc20;
    uVar3 = FUN_80020078(0x19f);
    if (uVar3 != 0) {
      *(undefined *)(param_2 + 0x408) = 6;
    }
  }
  else if (bVar1 < 5) {
    if (3 < bVar1) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dcc1c;
      iVar2 = FUN_8003809c(param_1,0x1a2);
      if (iVar2 != 0) {
        *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
        FUN_800201ac(0x19d,1);
        FUN_800201ac(0x1a3,1);
        FUN_800201ac(0xee5,1);
        FUN_800201ac(0xee6,1);
        *(undefined *)(param_2 + 0x408) = 5;
      }
    }
  }
  else if (bVar1 < 7) {
    *(undefined **)(param_2 + 0x48) = &DAT_803dcc24;
  }
  return;
}

