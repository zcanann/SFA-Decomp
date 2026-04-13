// Function: FUN_800243d0
// Entry: 800243d0
// Size: 464 bytes

void FUN_800243d0(short *param_1,undefined4 *param_2,int param_3,undefined4 *param_4,
                 undefined4 *param_5,int param_6,int param_7,int param_8)

{
  short sVar1;
  short sVar2;
  short *psVar3;
  undefined2 *puVar4;
  int in_r12;
  int iVar5;
  int unaff_r15;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  short *psVar9;
  short *psVar10;
  int iVar11;
  undefined8 uVar12;
  
  psVar9 = (short *)*param_4;
  psVar10 = (short *)*param_5;
  iVar11 = 0;
  iVar6 = 0x10000 - param_6;
LAB_800243f4:
  do {
    sVar1 = *psVar9;
    iVar7 = ((int)*psVar10 & 0x1fffU) - param_7;
    while( true ) {
      if (param_3 <= iVar11) {
        *param_4 = psVar9;
        *param_5 = psVar10;
        return;
      }
      if ((int)(((int)sVar1 & 0x1fffU) - param_7) <= iVar11) {
        if (iVar11 == iVar7) {
          FUN_800245a0();
          iVar7 = param_8;
          iVar5 = in_r12;
          uVar12 = FUN_800245a0();
          psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
          puVar4 = (undefined2 *)uVar12;
          param_8 = ((uint)(param_8 * iVar6 + iVar7 * param_6) >> 0x10) + (int)*psVar3;
          in_r12 = ((uint)(iVar5 * iVar6 + in_r12 * param_6) >> 0x10) + (int)psVar3[1];
          unaff_r15 = ((uint)(unaff_r15 * iVar6 + unaff_r15 * param_6) >> 0x10) + (int)psVar3[2];
          *puVar4 = (short)param_8;
          puVar4[1] = (short)in_r12;
          puVar4[2] = (short)unaff_r15;
          param_1 = psVar3 + 3;
          param_2 = (undefined4 *)(puVar4 + 3);
          iVar11 = iVar11 + 1;
        }
        else {
          uVar12 = FUN_800245a0();
          psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
          puVar4 = (undefined2 *)uVar12;
          param_8 = ((uint)(param_8 * iVar6) >> 0x10) + (int)*psVar3;
          in_r12 = ((uint)(in_r12 * iVar6) >> 0x10) + (int)psVar3[1];
          unaff_r15 = ((uint)(unaff_r15 * iVar6) >> 0x10) + (int)psVar3[2];
          *puVar4 = (short)param_8;
          puVar4[1] = (short)in_r12;
          puVar4[2] = (short)unaff_r15;
          param_1 = psVar3 + 3;
          param_2 = (undefined4 *)(puVar4 + 3);
          iVar11 = iVar11 + 1;
        }
        goto LAB_800243f4;
      }
      if (iVar7 <= iVar11) break;
      uVar8 = *(undefined4 *)param_1;
      sVar2 = param_1[2];
      param_1 = param_1 + 3;
      *param_2 = uVar8;
      iVar11 = iVar11 + 1;
      *(short *)(param_2 + 1) = sVar2;
      param_2 = (undefined4 *)((int)param_2 + 6);
    }
    uVar12 = FUN_800245a0();
    psVar3 = (short *)((ulonglong)uVar12 >> 0x20);
    puVar4 = (undefined2 *)uVar12;
    param_8 = ((uint)(param_8 * param_6) >> 0x10) + (int)*psVar3;
    in_r12 = ((uint)(in_r12 * param_6) >> 0x10) + (int)psVar3[1];
    unaff_r15 = ((uint)(unaff_r15 * param_6) >> 0x10) + (int)psVar3[2];
    *puVar4 = (short)param_8;
    puVar4[1] = (short)in_r12;
    puVar4[2] = (short)unaff_r15;
    param_1 = psVar3 + 3;
    param_2 = (undefined4 *)(puVar4 + 3);
    iVar11 = iVar11 + 1;
  } while( true );
}

