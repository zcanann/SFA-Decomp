// Function: FUN_8009e078
// Entry: 8009e078
// Size: 288 bytes

int FUN_8009e078(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,int param_11,undefined4 param_12)

{
  short *psVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  piVar3 = &DAT_8039c138;
  iVar5 = 0x50;
  piVar2 = piVar3;
  while ((((*(short *)(piVar2 + 3) == 0 || (piVar2[2] != param_9)) || (*piVar2 != param_10)) ||
         (piVar2[1] != param_11))) {
    piVar2 = piVar2 + 4;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
    if (iVar5 == 0) {
      iVar5 = 0;
      iVar6 = 0x50;
      do {
        if (*(short *)(piVar3 + 3) == 0) {
          (&DAT_8039c144)[iVar5 * 8] = 1;
          (&DAT_8039c140)[iVar5 * 4] = param_9;
          (&DAT_8039c138)[iVar5 * 4] = param_10;
          (&DAT_8039c13c)[iVar5 * 4] = param_11;
          (&DAT_8039c146)[iVar5 * 8] = (short)param_12;
          return (int)(short)iVar5;
        }
        piVar3 = piVar3 + 4;
        iVar5 = iVar5 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_expgfx_c__exptab_is_FULL_80310810,param_10,param_11,param_12,piVar2,piVar3,
                   iVar4,iVar5);
      return -1;
    }
  }
  psVar1 = &DAT_8039c144 + iVar4 * 8;
  if (*psVar1 == -1) {
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_expgfx_c__addToTable_usage_overf_803107e8,psVar1,param_11,param_12,piVar2,
                 &DAT_8039c138,iVar4,in_r10);
    return -1;
  }
  *psVar1 = *psVar1 + 1;
  return (int)(short)iVar4;
}

