// Function: FUN_80019b1c
// Entry: 80019b1c
// Size: 212 bytes

void FUN_80019b1c(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 local_18 [4];
  
  if ((DAT_803dc96c != 0) || ((param_2 & 1) != 0)) {
    DAT_803dc9ec = &DAT_8033af40 + param_1 * 0x28;
    DAT_803dc9e8 = param_1;
    if (param_1 == 2) {
      local_18[0] = DAT_803db3c8;
      FUN_800753b8(0,0,0xa00,0x780,local_18);
      DAT_803dc99c = 0;
    }
  }
  iVar2 = DAT_803dc9c8;
  if ((DAT_803dc96c == 0) || ((param_2 & 2) != 0)) {
    iVar1 = DAT_803dc9c8 * 5;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar1] = 0xf;
    (&DAT_8033a544)[iVar2 * 5] = param_1;
  }
  return;
}

