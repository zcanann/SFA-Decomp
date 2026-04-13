// Function: FUN_8028f054
// Entry: 8028f054
// Size: 780 bytes

/* WARNING: Type propagation algorithm not settling */

uint FUN_8028f054(uint param_1,uint param_2,int param_3,undefined4 *param_4)

{
  bool bVar1;
  bool bVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  undefined4 uVar7;
  char *pcVar8;
  undefined4 uVar9;
  char *local_28 [3];
  
  iVar4 = FUN_80292020((int)param_4,0);
  if (iVar4 == 0) {
    FUN_80292020((int)param_4,-1);
  }
  pcVar8 = (char *)(param_2 * param_3);
  if (((pcVar8 == (char *)0x0) || (*(char *)((int)param_4 + 10) != '\0')) ||
     (uVar3 = *(ushort *)(param_4 + 1) >> 6 & 7, uVar3 == 0)) {
    return 0;
  }
  if (uVar3 == 2) {
    FUN_8028fdd8();
  }
  bVar2 = true;
  bVar1 = false;
  if (((*(byte *)((int)param_4 + 5) >> 3 & 1) == 0) || ((*(byte *)(param_4 + 1) >> 1 & 3) == 2)) {
    bVar1 = true;
  }
  if ((!bVar1) && ((*(byte *)(param_4 + 1) >> 1 & 3) != 1)) {
    bVar2 = false;
  }
  if ((*(byte *)(param_4 + 2) >> 5 == 0) && ((*(byte *)(param_4 + 1) >> 3 & 2) != 0)) {
    if (((*(byte *)(param_4 + 1) >> 3 & 4) != 0) && (iVar4 = FUN_8028f578(param_4,0,2), iVar4 != 0))
    {
      return 0;
    }
    *(byte *)(param_4 + 2) = *(byte *)(param_4 + 2) & 0x1f | 0x20;
    FUN_8028f020((int)param_4);
  }
  if (*(byte *)(param_4 + 2) >> 5 != 1) {
    *(undefined *)((int)param_4 + 10) = 1;
    param_4[10] = 0;
    return 0;
  }
  iVar4 = 0;
  if (pcVar8 != (char *)0x0) {
    if ((param_4[9] != param_4[7]) || (bVar2)) {
      param_4[10] = param_4[8] - (param_4[9] - param_4[7]);
      while( true ) {
        pcVar6 = (char *)0x0;
        local_28[0] = (char *)param_4[10];
        if (pcVar8 < (char *)param_4[10]) {
          local_28[0] = pcVar8;
        }
        if ((((*(byte *)(param_4 + 1) >> 1 & 3) == 1) && (local_28[0] != (char *)0x0)) &&
           (pcVar6 = FUN_8028f9d4(param_1,'\n',(int)local_28[0]), pcVar6 != (char *)0x0)) {
          local_28[0] = pcVar6 + (1 - param_1);
        }
        if (local_28[0] != (char *)0x0) {
          FUN_80003494(param_4[9],param_1,(int)local_28[0]);
          param_1 = param_1 + (int)local_28[0];
          iVar4 = iVar4 + (int)local_28[0];
          pcVar8 = pcVar8 + -(int)local_28[0];
          param_4[9] = local_28[0] + param_4[9];
          param_4[10] = param_4[10] - (int)local_28[0];
        }
        if ((((param_4[10] == 0) || (pcVar6 != (char *)0x0)) ||
            ((*(byte *)(param_4 + 1) >> 1 & 3) == 0)) &&
           (iVar5 = FUN_8028ef5c(param_4,(undefined4 *)0x0), iVar5 != 0)) break;
        if ((pcVar8 == (char *)0x0) || (!bVar2)) goto LAB_8028f2bc;
      }
      *(undefined *)((int)param_4 + 10) = 1;
      pcVar8 = (char *)0x0;
      param_4[10] = 0;
    }
  }
LAB_8028f2bc:
  if ((pcVar8 != (char *)0x0) && (!bVar2)) {
    uVar7 = param_4[7];
    uVar9 = param_4[8];
    param_4[7] = param_1;
    param_4[8] = pcVar8;
    param_4[9] = param_1 + (int)pcVar8;
    iVar5 = FUN_8028ef5c(param_4,local_28);
    if (iVar5 != 0) {
      *(undefined *)((int)param_4 + 10) = 1;
      param_4[10] = 0;
    }
    param_4[7] = uVar7;
    iVar4 = iVar4 + (int)local_28[0];
    param_4[8] = uVar9;
    FUN_8028f020((int)param_4);
    param_4[10] = 0;
  }
  if ((*(byte *)(param_4 + 1) >> 1 & 3) != 2) {
    param_4[10] = 0;
  }
  return (iVar4 + (param_2 - 1)) / param_2;
}

