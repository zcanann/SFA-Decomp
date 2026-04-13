// Function: FUN_80009594
// Entry: 80009594
// Size: 280 bytes

void FUN_80009594(int param_1,int *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  if (param_1 < 0) {
    FUN_8007d858();
    FUN_802493c8(param_2);
    uVar1 = FUN_800238f8(0);
    FUN_800238c4((uint)param_2);
    FUN_800238f8(uVar1);
  }
  else {
    FUN_802493c8(param_2);
    uVar1 = FUN_800238f8(0);
    FUN_800238c4((uint)param_2);
    FUN_800238f8(uVar1);
    uVar2 = DAT_803dd4d4;
    DAT_803dd478 = DAT_803dd478 & 0xfffffffb;
    DAT_803dd474 = DAT_803dd474 | 4;
    if (DAT_803dd4d4 != 0) {
      uVar4 = DAT_803dd4d4 >> 3;
      iVar3 = DAT_803dd4d0;
      if (uVar4 != 0) {
        do {
          *(undefined *)(iVar3 + 0x15) = 0;
          *(undefined *)(iVar3 + 0x2b) = 0;
          *(undefined *)(iVar3 + 0x41) = 0;
          *(undefined *)(iVar3 + 0x57) = 0;
          *(undefined *)(iVar3 + 0x6d) = 0;
          *(undefined *)(iVar3 + 0x83) = 0;
          *(undefined *)(iVar3 + 0x99) = 0;
          *(undefined *)(iVar3 + 0xaf) = 0;
          iVar3 = iVar3 + 0xb0;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        uVar2 = uVar2 & 7;
        if (uVar2 == 0) {
          return;
        }
      }
      do {
        *(undefined *)(iVar3 + 0x15) = 0;
        uVar2 = uVar2 - 1;
        iVar3 = iVar3 + 0x16;
      } while (uVar2 != 0);
    }
  }
  return;
}

