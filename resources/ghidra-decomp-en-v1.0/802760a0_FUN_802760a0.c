// Function: FUN_802760a0
// Entry: 802760a0
// Size: 640 bytes

void FUN_802760a0(int param_1,uint *param_2)

{
  short sVar1;
  ushort uVar2;
  ushort uVar3;
  uint uVar4;
  int iVar5;
  undefined *puVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  double local_30;
  double local_20;
  
  puVar6 = (undefined *)FUN_80275058(*param_2 >> 8 & 0xffff);
  if (puVar6 != (undefined *)0x0) {
    *(short *)(param_1 + 0x204) = (short)((int)(char)param_2[1] << 8);
    sVar1 = *(short *)(param_1 + 0x204);
    if (sVar1 < 0) {
      uVar4 = (uint)(short)(char)(param_2[1] >> 8);
      uVar8 = uVar4 << 8;
      iVar5 = (int)uVar8 / 100 + ((int)(uVar8 | uVar4 >> 0x18) >> 0x1f);
      *(short *)(param_1 + 0x204) = sVar1 - ((short)iVar5 - (short)(iVar5 >> 0x1f));
    }
    else {
      uVar4 = (uint)(short)(char)(param_2[1] >> 8);
      uVar8 = uVar4 << 8;
      iVar5 = (int)uVar8 / 100 + ((int)(uVar8 | uVar4 >> 0x18) >> 0x1f);
      *(short *)(param_1 + 0x204) = sVar1 + ((short)iVar5 - (short)(iVar5 >> 0x1f));
    }
    uVar2 = *(ushort *)(puVar6 + 8);
    uVar8 = CONCAT13(puVar6[0xf],CONCAT12(puVar6[0xe],CONCAT11(puVar6[0xd],puVar6[0xc])));
    uVar3 = *(ushort *)(puVar6 + 10);
    iVar5 = CONCAT13(puVar6[3],CONCAT12(puVar6[2],CONCAT11(puVar6[1],*puVar6)));
    iVar9 = CONCAT13(puVar6[7],CONCAT12(puVar6[6],CONCAT11(puVar6[5],puVar6[4])));
    uVar4 = CONCAT13(puVar6[0x13],CONCAT12(puVar6[0x12],CONCAT11(puVar6[0x11],puVar6[0x10])));
    if (uVar8 != 0x80000000) {
      local_20 = (double)CONCAT44(0x43300000,*(undefined4 *)(param_1 + 0x158));
      iVar5 = iVar5 + (int)(FLOAT_803e77f4 * (float)(local_20 - DOUBLE_803e7800) *
                           (float)((double)CONCAT44(0x43300000,uVar8 ^ 0x80000000) - DOUBLE_803e7808
                                  ));
    }
    if (uVar4 != 0x80000000) {
      local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x12f));
      iVar9 = iVar9 + (int)(FLOAT_803e77f8 * (float)(local_30 - DOUBLE_803e7800) *
                           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7808
                                  ));
    }
    *(undefined *)(param_1 + 0x1dc) = 1;
    *(undefined *)(param_1 + 0x202) = 0;
    uVar7 = FUN_8027a60c(iVar5);
    *(undefined4 *)(param_1 + 0x1f0) = uVar7;
    uVar7 = FUN_8027a60c(iVar9);
    uVar8 = (int)((uVar2 & 0xff) << 8 | (int)(uint)uVar2 >> 8) >> 2;
    *(undefined4 *)(param_1 + 500) = uVar7;
    if (0x3ff < uVar8) {
      uVar8 = 0x3ff;
    }
    *(ushort *)(param_1 + 0x1f8) = 0xc1 - (ushort)(byte)(&DAT_8032f79c)[uVar8];
    *(uint *)(param_1 + 0x1fc) = (uVar3 & 0xff) << 8 | (int)(uint)uVar3 >> 8;
    FUN_8027a8d4(param_1 + 0x1dc);
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x200;
  }
  return;
}

