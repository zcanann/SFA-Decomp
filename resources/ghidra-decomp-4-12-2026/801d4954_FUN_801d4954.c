// Function: FUN_801d4954
// Entry: 801d4954
// Size: 320 bytes

void FUN_801d4954(short *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  
  iVar1 = FUN_8002bac4();
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
  uVar2 = FUN_80020078(0xc48);
  if (uVar2 == 0) {
    uVar2 = FUN_80020078(0x23c);
    if (uVar2 == 0) {
      uVar2 = FUN_80020078(0x5bd);
      if (uVar2 == 0) {
        uVar2 = FUN_80020078(0xa31);
        if (uVar2 == 0) {
          *(undefined **)(param_2 + 0x38) = &DAT_803dcc40;
        }
        else {
          *(undefined **)(param_2 + 0x38) = &DAT_803dcc54;
        }
      }
      else {
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        uVar2 = FUN_80296c50(iVar1,3);
        if ((uVar2 != 0) &&
           (dVar3 = FUN_80021730((float *)(iVar1 + 0x18),(float *)(param_1 + 0xc)),
           dVar3 < (double)FLOAT_803e6094)) {
          FUN_800201ac(0x23b,1);
        }
      }
    }
    else {
      *(undefined **)(param_2 + 0x38) = &DAT_803dcc44;
    }
  }
  else {
    *(undefined **)(param_2 + 0x38) = &DAT_803dcc54;
  }
  iVar1 = FUN_8002bac4();
  *(undefined *)(param_2 + 8) = 1;
  *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(iVar1 + 0xc);
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar1 + 0x10);
  *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(iVar1 + 0x14);
  FUN_8003b5f8(param_1,(char *)(param_2 + 8));
  return;
}

