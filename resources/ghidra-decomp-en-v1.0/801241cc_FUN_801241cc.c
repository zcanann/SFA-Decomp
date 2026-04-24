// Function: FUN_801241cc
// Entry: 801241cc
// Size: 272 bytes

int FUN_801241cc(short *param_1,char param_2)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  
  iVar2 = 0;
  psVar3 = param_1;
  if (param_2 == '\0') {
    for (; -1 < *psVar3; psVar3 = psVar3 + 8) {
      iVar1 = FUN_8001ffb4();
      if (iVar1 != 0) {
        if (param_1 == &DAT_8031b4e0) {
          if ((psVar3[2] < 0) || (iVar1 = FUN_8001ffb4(), iVar1 == 0)) {
            iVar2 = iVar2 + 1;
          }
        }
        else if (((psVar3[1] < 0) || (iVar1 = FUN_8001ffb4(), iVar1 == 0)) &&
                ((psVar3[2] < 0 || (iVar1 = FUN_8001ffb4(), iVar1 == 0)))) {
          iVar2 = iVar2 + 1;
        }
      }
    }
  }
  else if (0 < (int)DAT_803dd738) {
    for (; -1 < *param_1; param_1 = param_1 + 8) {
      if ((DAT_803dd738 != 0xffffffff) && ((DAT_803dd738 & (int)*param_1) != 0)) {
        iVar2 = iVar2 + 1;
      }
    }
  }
  return iVar2;
}

