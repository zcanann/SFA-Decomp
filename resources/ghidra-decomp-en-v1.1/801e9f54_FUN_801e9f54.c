// Function: FUN_801e9f54
// Entry: 801e9f54
// Size: 740 bytes

/* WARNING: Removing unreachable block (ram,0x801ea218) */
/* WARNING: Removing unreachable block (ram,0x801ea210) */
/* WARNING: Removing unreachable block (ram,0x801e9f6c) */
/* WARNING: Removing unreachable block (ram,0x801e9f64) */

void FUN_801e9f54(void)

{
  float *pfVar1;
  int extraout_r4;
  int iVar2;
  int iVar3;
  int iVar4;
  double in_f30;
  double dVar5;
  double in_f31;
  double dVar6;
  double in_ps30_1;
  double in_ps31_1;
  undefined local_48;
  undefined local_47;
  undefined local_46 [2];
  undefined4 local_44;
  undefined4 local_40;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  FUN_80286840();
  local_40 = DAT_803e677c;
  FUN_8004c460(DAT_803de8e0,0);
  FUN_80079b3c();
  FUN_8007986c();
  FUN_80079980();
  local_44 = local_40;
  FUN_8025c428(2,(byte *)&local_44);
  FUN_8007048c(1,3,0);
  FUN_8025cce8(1,4,5,5);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  pfVar1 = (float *)FUN_8000f56c();
  FUN_8025d80c(pfVar1,0);
  FUN_8025d888(0);
  FUN_80089b54(0,local_46,&local_47,&local_48);
  iVar3 = 0;
  iVar4 = extraout_r4;
  do {
    if (((*(byte *)(iVar4 + 0x4ce) & 1) != 0) && (3 < *(short *)(iVar4 + 0x4cc))) {
      pfVar1 = *(float **)(iVar4 + 0x4c8);
      dVar5 = (double)FLOAT_803e6780;
      dVar6 = (double)FLOAT_803e6784;
      for (iVar2 = 0; iVar2 < *(short *)(iVar4 + 0x4cc) + -2; iVar2 = iVar2 + 2) {
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = *pfVar1 - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[1];
        DAT_cc008000 = pfVar1[2] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = local_46[0];
        DAT_cc008000._0_1_ = local_47;
        DAT_cc008000._0_1_ = local_48;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 3);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = pfVar1[4] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[5];
        DAT_cc008000 = pfVar1[6] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = local_46[0];
        DAT_cc008000._0_1_ = local_47;
        DAT_cc008000._0_1_ = local_48;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 7);
        DAT_cc008000 = (float)dVar6;
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = pfVar1[0xc] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[0xd];
        DAT_cc008000 = pfVar1[0xe] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = local_46[0];
        DAT_cc008000._0_1_ = local_47;
        DAT_cc008000._0_1_ = local_48;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 0xf);
        DAT_cc008000 = (float)dVar6;
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = pfVar1[8] - FLOAT_803dda58;
        DAT_cc008000 = pfVar1[9];
        DAT_cc008000 = pfVar1[10] - FLOAT_803dda5c;
        DAT_cc008000._0_1_ = local_46[0];
        DAT_cc008000._0_1_ = local_47;
        DAT_cc008000._0_1_ = local_48;
        DAT_cc008000._0_1_ = (char)*(undefined2 *)(pfVar1 + 0xb);
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar5;
        pfVar1 = pfVar1 + 8;
      }
    }
    iVar4 = iVar4 + 8;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 9);
  FUN_8028688c();
  return;
}

