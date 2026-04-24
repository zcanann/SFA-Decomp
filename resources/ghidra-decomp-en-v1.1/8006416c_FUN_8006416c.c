// Function: FUN_8006416c
// Entry: 8006416c
// Size: 220 bytes

int FUN_8006416c(double param_1,double param_2,double param_3,undefined2 param_4,int param_5)

{
  int iVar1;
  float *pfVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar1 = (int)DAT_803ddbdc;
  pfVar2 = DAT_803ddbb8;
  iVar4 = iVar1;
  if (0 < iVar1) {
    do {
      if (((param_1 == (double)*pfVar2) && (param_2 == (double)pfVar2[1])) &&
         (param_3 == (double)pfVar2[2])) {
        *(undefined2 *)(param_5 + iVar3 * 4 + 2) = param_4;
        return iVar3;
      }
      pfVar2 = pfVar2 + 3;
      iVar3 = iVar3 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  DAT_803ddbb8[iVar1 * 3] = (float)param_1;
  DAT_803ddbb8[DAT_803ddbdc * 3 + 1] = (float)param_2;
  DAT_803ddbb8[DAT_803ddbdc * 3 + 2] = (float)param_3;
  *(undefined2 *)(param_5 + DAT_803ddbdc * 4) = param_4;
  *(undefined2 *)(param_5 + DAT_803ddbdc * 4 + 2) = 0xffff;
  DAT_803ddbdc = DAT_803ddbdc + 1;
  return DAT_803ddbdc + -1;
}

