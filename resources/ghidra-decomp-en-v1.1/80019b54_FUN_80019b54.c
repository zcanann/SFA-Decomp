// Function: FUN_80019b54
// Entry: 80019b54
// Size: 212 bytes

void FUN_80019b54(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 local_18 [4];
  
  if ((DAT_803dd5ec != 0) || ((param_2 & 1) != 0)) {
    DAT_803dd66c = &DAT_8033bba0 + param_1 * 0x28;
    DAT_803dd668 = param_1;
    if (param_1 == 2) {
      local_18[0] = DAT_803dc028;
      FUN_80075534(0,0,0xa00,0x780,local_18);
      DAT_803dd61c = 0;
    }
  }
  iVar2 = DAT_803dd648;
  if ((DAT_803dd5ec == 0) || ((param_2 & 2) != 0)) {
    iVar1 = DAT_803dd648 * 5;
    DAT_803dd648 = DAT_803dd648 + 1;
    (&DAT_8033b1a0)[iVar1] = 0xf;
    (&DAT_8033b1a4)[iVar2 * 5] = param_1;
  }
  return;
}

