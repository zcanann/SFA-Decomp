// Function: FUN_8027c000
// Entry: 8027c000
// Size: 320 bytes

int FUN_8027c000(short param_1,short param_2,int *param_3,uint *param_4,char param_5,
                undefined param_6)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  
  piVar3 = &DAT_803cc840;
  iVar2 = 0;
  iVar1 = (int)DAT_803def88;
  if (0 < iVar1) {
    do {
      if (param_1 == *(short *)(*piVar3 + 4)) {
        iVar1 = (&DAT_803cc840)[iVar2 * 3];
        if (*(short *)(iVar1 + 6) != 0) {
          return -1;
        }
        iVar2 = (&DAT_803cc848)[iVar2 * 3];
        iVar6 = iVar2 + *(int *)(iVar1 + 0x1c);
        iVar5 = iVar2 + *(int *)(iVar1 + 0x20);
        psVar4 = (short *)(iVar2 + *(int *)(iVar1 + 0x24));
        while( true ) {
          if (*psVar4 == -1) {
            return -1;
          }
          if (*psVar4 == param_2) break;
          psVar4 = psVar4 + 0x2a;
        }
        if (param_5 != '\0') {
          iVar1 = FUN_8026cbec(iVar6,iVar5,(int)psVar4,param_3,param_4,param_6,param_1);
          return iVar1;
        }
        FUN_80285258();
        iVar1 = FUN_8026cbec(iVar6,iVar5,(int)psVar4,param_3,param_4,param_6,param_1);
        FUN_80285220();
        return iVar1;
      }
      piVar3 = piVar3 + 3;
      iVar2 = iVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return -1;
}

