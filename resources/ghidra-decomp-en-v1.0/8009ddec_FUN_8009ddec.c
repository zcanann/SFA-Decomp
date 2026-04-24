// Function: FUN_8009ddec
// Entry: 8009ddec
// Size: 288 bytes

int FUN_8009ddec(int param_1,int param_2,int param_3,undefined2 param_4)

{
  short sVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = 0;
  piVar3 = &DAT_8039b4d8;
  iVar5 = 0x50;
  piVar2 = piVar3;
  while ((((*(short *)(piVar2 + 3) == 0 || (piVar2[2] != param_1)) || (*piVar2 != param_2)) ||
         (piVar2[1] != param_3))) {
    piVar2 = piVar2 + 4;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
    if (iVar5 == 0) {
      iVar4 = 0;
      iVar5 = 0x50;
      do {
        if (*(short *)(piVar3 + 3) == 0) {
          (&DAT_8039b4e4)[iVar4 * 8] = 1;
          (&DAT_8039b4e0)[iVar4 * 4] = param_1;
          (&DAT_8039b4d8)[iVar4 * 4] = param_2;
          (&DAT_8039b4dc)[iVar4 * 4] = param_3;
          (&DAT_8039b4e6)[iVar4 * 8] = param_4;
          return (int)(short)iVar4;
        }
        piVar3 = piVar3 + 4;
        iVar4 = iVar4 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      FUN_801378a8(s_expgfx_c__exptab_is_FULL_8030fc50);
      return -1;
    }
  }
  sVar1 = (&DAT_8039b4e4)[iVar4 * 8];
  if (sVar1 == -1) {
    FUN_801378a8(s_expgfx_c__addToTable_usage_overf_8030fc28);
    return -1;
  }
  (&DAT_8039b4e4)[iVar4 * 8] = sVar1 + 1;
  return (int)(short)iVar4;
}

