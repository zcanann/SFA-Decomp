// Function: FUN_801d4364
// Entry: 801d4364
// Size: 320 bytes

void FUN_801d4364(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  double dVar3;
  
  iVar1 = FUN_8002b9ec();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  iVar2 = FUN_8001ffb4(0xc48);
  if (iVar2 == 0) {
    iVar2 = FUN_8001ffb4(0x23c);
    if (iVar2 == 0) {
      iVar2 = FUN_8001ffb4(0x5bd);
      if (iVar2 == 0) {
        iVar1 = FUN_8001ffb4(0xa31);
        if (iVar1 == 0) {
          *(undefined **)(param_2 + 0x38) = &DAT_803dbfd8;
        }
        else {
          *(undefined **)(param_2 + 0x38) = &DAT_803dbfec;
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        iVar2 = FUN_802964f0(iVar1,3);
        if ((iVar2 != 0) &&
           (dVar3 = (double)FUN_8002166c(iVar1 + 0x18,param_1 + 0x18),
           dVar3 < (double)FLOAT_803e53fc)) {
          FUN_800200e8(0x23b,1);
        }
      }
    }
    else {
      *(undefined **)(param_2 + 0x38) = &DAT_803dbfdc;
    }
  }
  else {
    *(undefined **)(param_2 + 0x38) = &DAT_803dbfec;
  }
  iVar1 = FUN_8002b9ec();
  *(undefined *)(param_2 + 8) = 1;
  *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(iVar1 + 0xc);
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar1 + 0x10);
  *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(iVar1 + 0x14);
  FUN_8003b500((double)FLOAT_803e53f8,param_1,param_2 + 8);
  return;
}

