// Function: FUN_801244b0
// Entry: 801244b0
// Size: 272 bytes

int FUN_801244b0(short *param_1,char param_2)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  
  iVar2 = 0;
  psVar3 = param_1;
  if (param_2 == '\0') {
    for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
      uVar1 = FUN_80020078((int)*psVar3);
      if (uVar1 != 0) {
        if (param_1 == &DAT_8031c130) {
          if ((psVar3[2] < 0) || (uVar1 = FUN_80020078((int)psVar3[2]), uVar1 == 0)) {
            iVar2 = iVar2 + 1;
          }
        }
        else if (((psVar3[1] < 0) || (uVar1 = FUN_80020078((int)psVar3[1]), uVar1 == 0)) &&
                ((psVar3[2] < 0 || (uVar1 = FUN_80020078((int)psVar3[2]), uVar1 == 0)))) {
          iVar2 = iVar2 + 1;
        }
      }
    }
  }
  else if (0 < (int)DAT_803de3b8) {
    for (; -1 < *param_1; param_1 = param_1 + 8) {
      if ((DAT_803de3b8 != 0xffffffff) && ((DAT_803de3b8 & (int)*param_1) != 0)) {
        iVar2 = iVar2 + 1;
      }
    }
  }
  return iVar2;
}

