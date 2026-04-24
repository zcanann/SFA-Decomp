// Function: FUN_80085dc4
// Entry: 80085dc4
// Size: 660 bytes

short * FUN_80085dc4(short *param_1,short **param_2,int param_3)

{
  short *psVar1;
  short **ppsVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int iVar7;
  float local_18 [2];
  
  *(byte *)((int)param_2 + 0x79) = *(byte *)((int)param_2 + 0x79) ^ 1;
  if (*(char *)((int)param_2 + 0x79) == '\0') {
    if (*param_2 != (short *)0x0) {
      if ((*(ushort *)((int)param_2 + 0x6e) & 1) != 0) {
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_1 + 10);
        FUN_800849e8();
      }
      if ((*(char *)((int)param_2 + 0x7a) == '\x01') &&
         (iVar3 = FUN_800658a4((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                               (double)*(float *)(param_1 + 10),param_1,local_18,0), iVar3 == 0)) {
        *(float *)(param_1 + 8) =
             *(float *)(param_1 + 8) +
             ((*(float *)(param_1 + 8) - local_18[0]) - *(float *)(param_3 + 0xc));
      }
      if ((*(ushort *)((int)param_2 + 0x6e) & 2) != 0) {
        *param_1 = *param_1 + *(short *)((int)param_2 + 0x1a);
      }
      *(undefined4 *)(param_1 + 0x60) = 0;
      param_1[0x58] = param_1[0x58] & 0xefff;
      *param_2 = (short *)0x0;
    }
  }
  else {
    FUN_8008196c();
    psVar1 = *param_2;
    if (psVar1 != (short *)0x0) {
      *(short **)(psVar1 + 0x60) = param_1;
      psVar1[0x58] = psVar1[0x58] | 0x1000;
      param_2[0x44] = psVar1;
      psVar6 = *param_2;
      iVar4 = 0;
      iVar3 = *(char *)((int)param_2 + 0x57) * 0x80;
      iVar7 = 2;
      ppsVar2 = (short **)(&DAT_80396918 + iVar3);
      while ((iVar5 = iVar4, *ppsVar2 != (short *)0x0 && (*ppsVar2 != psVar6))) {
        iVar5 = iVar4 + 1;
        if ((ppsVar2[2] == (short *)0x0) || (ppsVar2[2] == psVar6)) break;
        iVar5 = iVar4 + 2;
        if ((ppsVar2[4] == (short *)0x0) || (ppsVar2[4] == psVar6)) break;
        iVar5 = iVar4 + 3;
        if ((ppsVar2[6] == (short *)0x0) || (ppsVar2[6] == psVar6)) break;
        iVar5 = iVar4 + 4;
        if ((ppsVar2[8] == (short *)0x0) || (ppsVar2[8] == psVar6)) break;
        iVar5 = iVar4 + 5;
        if ((ppsVar2[10] == (short *)0x0) || (ppsVar2[10] == psVar6)) break;
        iVar5 = iVar4 + 6;
        if ((ppsVar2[0xc] == (short *)0x0) || (ppsVar2[0xc] == psVar6)) break;
        iVar5 = iVar4 + 7;
        if ((ppsVar2[0xe] == (short *)0x0) || (ppsVar2[0xe] == psVar6)) break;
        ppsVar2 = ppsVar2 + 0x10;
        iVar4 = iVar4 + 8;
        iVar7 = iVar7 + -1;
        iVar5 = iVar4;
        if (iVar7 == 0) break;
      }
      *(short **)((int)(&DAT_80396918 + iVar3) + iVar5 * 2 * 4) = psVar6;
      *(short **)(&DAT_8039691c + iVar3 + iVar5 * 8) = param_1;
      param_1 = psVar1;
    }
  }
  return param_1;
}

