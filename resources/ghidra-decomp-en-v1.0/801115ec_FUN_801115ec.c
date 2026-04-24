// Function: FUN_801115ec
// Entry: 801115ec
// Size: 188 bytes

void FUN_801115ec(char param_1)

{
  int iVar1;
  
  if (param_1 != DAT_803dd5d2) {
    if (DAT_803dd5d1 == '\x04') {
      if (FLOAT_803e1be0 == FLOAT_803db9d8) {
        FUN_8000a518(0xbe,1);
        FUN_8000a518(0xc1,1);
      }
      else {
        iVar1 = FUN_800e7f38();
        FUN_80117b68(0,1000);
        FUN_80009a28(*(undefined *)(iVar1 + 10),1000,1,0,0);
      }
    }
    DAT_803dd5d1 = DAT_803dd5d2;
    FLOAT_803db9d8 = FLOAT_803e1be4;
    DAT_803dd5d0 = 1;
    DAT_803dd5d2 = param_1;
  }
  return;
}

