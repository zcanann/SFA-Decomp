// Function: FUN_800e31e0
// Entry: 800e31e0
// Size: 568 bytes

int FUN_800e31e0(int param_1,int param_2,int param_3,int *param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  int local_28 [7];
  
  if (param_1 == 0) {
    local_28[0] = -1;
  }
  else {
    iVar2 = 0;
    iVar10 = 4;
    iVar7 = param_1;
    do {
      uVar9 = *(uint *)(iVar7 + 0x1c);
      if (-1 < (int)uVar9) {
        if ((int)uVar9 < 0) {
          iVar8 = 0;
        }
        else {
          iVar3 = 0;
          iVar6 = DAT_803de0f0 + -1;
          while (iVar3 <= iVar6) {
            iVar4 = iVar6 + iVar3 >> 1;
            iVar8 = (&DAT_803a2448)[iVar4];
            if (*(uint *)(iVar8 + 0x14) < uVar9) {
              iVar3 = iVar4 + 1;
            }
            else {
              if (*(uint *)(iVar8 + 0x14) <= uVar9) goto LAB_800e3290;
              iVar6 = iVar4 + -1;
            }
          }
          iVar8 = 0;
        }
LAB_800e3290:
        for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
          iVar3 = iVar2;
          if ((int)*(char *)(iVar8 + 0x19) == *(int *)(param_2 + iVar6 * 4)) {
            iVar3 = iVar2 + 1;
            local_28[iVar2] = *(int *)(iVar7 + 0x1c);
            iVar6 = param_3;
          }
          iVar2 = iVar3;
        }
      }
      iVar7 = iVar7 + 4;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    if (iVar2 == 0) {
      local_28[0] = -1;
    }
    else if (iVar2 == 1) {
      *param_4 = *(int *)(param_1 + 0x14);
    }
    else if (iVar2 < 2) {
      local_28[0] = -1;
    }
    else {
      iVar7 = 0;
      for (iVar10 = 0; iVar10 < iVar2; iVar10 = iVar10 + 1) {
        piVar5 = (int *)((int)local_28 + iVar7);
        if (*param_4 == *piVar5) {
          uVar9 = (iVar2 + -1) - iVar10;
          if (iVar10 < iVar2 + -1) {
            uVar11 = uVar9 >> 3;
            uVar1 = uVar9;
            if (uVar11 == 0) goto LAB_800e33ac;
            do {
              *piVar5 = piVar5[1];
              piVar5[1] = piVar5[2];
              piVar5[2] = piVar5[3];
              piVar5[3] = piVar5[4];
              piVar5[4] = piVar5[5];
              piVar5[5] = piVar5[6];
              piVar5[6] = piVar5[7];
              piVar5[7] = piVar5[8];
              piVar5 = piVar5 + 8;
              iVar7 = iVar7 + 0x20;
              uVar11 = uVar11 - 1;
            } while (uVar11 != 0);
            for (uVar1 = uVar9 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
LAB_800e33ac:
              *piVar5 = piVar5[1];
              piVar5 = piVar5 + 1;
              iVar7 = iVar7 + 4;
            }
            iVar10 = iVar10 + uVar9;
          }
          iVar2 = iVar2 + -1;
        }
        iVar7 = iVar7 + 4;
      }
      *param_4 = *(int *)(param_1 + 0x14);
      uVar9 = FUN_80022264(0,iVar2 - 1);
      local_28[0] = local_28[uVar9];
    }
  }
  return local_28[0];
}

