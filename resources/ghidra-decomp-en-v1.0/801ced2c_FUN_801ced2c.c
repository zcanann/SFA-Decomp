// Function: FUN_801ced2c
// Entry: 801ced2c
// Size: 224 bytes

void FUN_801ced2c(undefined4 param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 5) {
    *(undefined **)(param_2 + 0x48) = &DAT_803dbfb8;
    iVar2 = FUN_8001ffb4(0x19f);
    if (iVar2 != 0) {
      *(undefined *)(param_2 + 0x408) = 6;
    }
  }
  else if (bVar1 < 5) {
    if (3 < bVar1) {
      *(undefined **)(param_2 + 0x48) = &DAT_803dbfb4;
      iVar2 = FUN_80037fa4(param_1,0x1a2);
      if (iVar2 != 0) {
        *(byte *)(param_2 + 0x43c) = *(byte *)(param_2 + 0x43c) | 0x10;
        FUN_800200e8(0x19d,1);
        FUN_800200e8(0x1a3,1);
        FUN_800200e8(0xee5,1);
        FUN_800200e8(0xee6,1);
        *(undefined *)(param_2 + 0x408) = 5;
      }
    }
  }
  else if (bVar1 < 7) {
    *(undefined **)(param_2 + 0x48) = &DAT_803dbfbc;
  }
  return;
}

