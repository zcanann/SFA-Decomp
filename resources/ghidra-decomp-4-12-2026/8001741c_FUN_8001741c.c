// Function: FUN_8001741c
// Entry: 8001741c
// Size: 80 bytes

void FUN_8001741c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  iVar1 = DAT_803dd648 * 5;
  if (param_1 == 0xff) {
    DAT_803dd64c = (undefined *)0x0;
  }
  else {
    DAT_803dd64c = &DAT_802c7b80 + param_1 * 0x20;
  }
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 8;
  (&DAT_8033b1a4)[iVar2 * 5] = param_1;
  return;
}

