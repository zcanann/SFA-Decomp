// Function: FUN_801a3434
// Entry: 801a3434
// Size: 576 bytes

void FUN_801a3434(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined uVar1;
  float fVar2;
  undefined uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 uVar15;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  uVar15 = FUN_80286824();
  iVar4 = (int)((ulonglong)uVar15 >> 0x20);
  iVar7 = (int)uVar15;
  iVar12 = (uint)*(byte *)(param_12 + 0x6e5) * 0x10;
  iVar10 = *(int *)(&DAT_803239f4 + iVar12);
  *(undefined4 *)(param_12 + 0x6d0) = *(undefined4 *)(&DAT_803239f8 + iVar12);
  uVar1 = (&DAT_803239fc)[(uint)*(byte *)(param_12 + 0x6e5) * 0x10];
  if (iVar10 != -1) {
    iVar13 = 0;
    iVar12 = param_12;
    iVar14 = param_12;
    for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(param_12 + 0x6d4); iVar11 = iVar11 + 1) {
      *(undefined *)(param_12 + iVar11 + 0x6d5) = 1;
      *(undefined *)(iVar14 + 0x6d) = uVar1;
      fVar2 = FLOAT_803e5000;
      if (param_11 == 0) {
        *(float *)(iVar14 + 4) = FLOAT_803e5000;
        *(float *)(iVar14 + 8) = fVar2;
        *(float *)(iVar14 + 0xc) = fVar2;
        iVar8 = **(int **)(*(int *)(iVar4 + 0x7c) + iVar13);
        local_5c = fVar2;
        local_58 = fVar2;
        local_54 = fVar2;
        for (iVar9 = 0; param_2 = DOUBLE_803e4ff8, uVar6 = (uint)*(ushort *)(iVar8 + 0xe4),
            iVar9 < (int)uVar6; iVar9 = iVar9 + 1) {
          FUN_80026ec4(iVar8,iVar9,&local_68);
          local_5c = local_68 + local_5c;
          local_58 = local_64 + local_58;
          local_54 = local_60 + local_54;
        }
        param_3 = (double)FLOAT_803e5004;
        local_50 = 0x43300000;
        *(float *)(iVar14 + 4) =
             local_5c *
             (float)(param_3 / (double)(float)((double)CONCAT44(0x43300000,uVar6) - DOUBLE_803e4ff8)
                    );
        uStack_44 = (uint)*(ushort *)(iVar8 + 0xe4);
        local_48 = 0x43300000;
        *(float *)(iVar14 + 8) =
             local_58 *
             (float)(param_3 / (double)(float)((double)CONCAT44(0x43300000,uStack_44) - param_2));
        uStack_3c = (uint)*(ushort *)(iVar8 + 0xe4);
        local_40 = 0x43300000;
        *(float *)(iVar14 + 0xc) =
             local_54 *
             (float)(param_3 / (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - param_2));
        uStack_4c = uVar6;
      }
      *(undefined4 *)(iVar14 + 0x10) = *(undefined4 *)(iVar14 + 4);
      *(undefined4 *)(iVar14 + 0x14) = *(undefined4 *)(iVar14 + 8);
      *(undefined4 *)(iVar14 + 0x18) = *(undefined4 *)(iVar14 + 0xc);
      uVar15 = FUN_801a3674(iVar4,iVar14,iVar7);
      *(undefined *)(iVar14 + 0x6b) = 0xff;
      uVar6 = FUN_80020078((int)*(short *)(iVar7 + 0x3e));
      if (uVar6 == 0) {
        uVar3 = 0;
      }
      else {
        uVar3 = 2;
      }
      *(undefined *)(iVar14 + 0x6a) = uVar3;
      uVar5 = FUN_801a3190(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,
                           (short)iVar10,iVar14,(char)iVar11,param_13,param_14,param_15,param_16);
      *(undefined4 *)(iVar12 + 0x690) = uVar5;
      iVar14 = iVar14 + 0x70;
      iVar13 = iVar13 + 4;
      iVar12 = iVar12 + 4;
    }
    uVar6 = FUN_80020078((int)*(short *)(iVar7 + 0x3e));
    *(bool *)(param_12 + 0x6e4) = uVar6 != 0;
  }
  FUN_80286870();
  return;
}

