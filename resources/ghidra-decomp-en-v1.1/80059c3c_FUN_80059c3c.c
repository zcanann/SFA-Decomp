// Function: FUN_80059c3c
// Entry: 80059c3c
// Size: 364 bytes

int FUN_80059c3c(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = 0;
  iVar7 = 0x40;
  pcVar3 = DAT_80382ea4;
  psVar4 = DAT_80382e9c;
  iVar5 = DAT_80382ea8;
  while (((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] != (int)*pcVar3 ||
           (iVar1 = (int)*psVar4, param_1 < iVar1)) || (psVar4[1] < param_1)) ||
         (((param_2 < psVar4[2] || (psVar4[3] < param_2)) ||
          (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[2]) * ((psVar4[1] - iVar1) + 1),
          (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + ((int)uVar2 >> 3))) == 0))))) {
    if ((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] == (int)pcVar3[1]) &&
        (iVar1 = (int)psVar4[5], iVar1 <= param_1)) &&
       ((param_1 <= psVar4[6] &&
        (((psVar4[7] <= param_2 && (param_2 <= psVar4[8])) &&
         (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[7]) * ((psVar4[6] - iVar1) + 1),
         (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + 0x40 + ((int)uVar2 >> 3))) != 0)))))) {
      return iVar6 + 1;
    }
    psVar4 = psVar4 + 10;
    iVar5 = iVar5 + 0x80;
    pcVar3 = pcVar3 + 2;
    iVar6 = iVar6 + 2;
    iVar7 = iVar7 + -1;
    if (iVar7 == 0) {
      return -1;
    }
  }
  return iVar6;
}

