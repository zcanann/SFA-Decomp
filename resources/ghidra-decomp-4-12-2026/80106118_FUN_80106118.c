// Function: FUN_80106118
// Entry: 80106118
// Size: 1904 bytes

void FUN_80106118(undefined2 *param_1,int param_2,int param_3)

{
  float *pfVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  uint uVar5;
  int iVar6;
  short *psVar7;
  undefined local_58 [4];
  undefined auStack_54 [4];
  float local_50;
  undefined auStack_4c [4];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  *(byte *)((int)DAT_803de1a8 + 0xc6) = *(byte *)((int)DAT_803de1a8 + 0xc6) & 0x7f;
  *(undefined *)(DAT_803de1a8 + 0x31) = 0;
  *(undefined *)((int)DAT_803de1a8 + 0xc3) = 0;
  *(undefined *)((int)DAT_803de1a8 + 199) = 0;
  *(byte *)(DAT_803de1a8 + 0x32) = *(byte *)(DAT_803de1a8 + 0x32) & 0x7f;
  *(undefined *)((int)DAT_803de1a8 + 0xc2) = 8;
  psVar7 = *(short **)(param_1 + 0x52);
  if (param_2 == 2) {
    if (param_3 == 0) {
      DAT_803de1a8[0x25] = DAT_803de1a8[0x24];
      pfVar1 = DAT_803de1a8 + 0xf;
      DAT_803de1a8[0x26] = *pfVar1;
      DAT_803de1a8[0x10] = *pfVar1;
      pfVar1 = DAT_803de1a8 + 0x11;
      DAT_803de1a8[0x27] = *pfVar1;
      DAT_803de1a8[0x12] = *pfVar1;
      DAT_803de1a8[0xc] = DAT_803de1a8[0xb];
      DAT_803de1a8[0xe] = DAT_803de1a8[0xd];
      DAT_803de1a8[0x1c] = DAT_803de1a8[0x1b];
      DAT_803de1a8[0x18] = DAT_803de1a8[0x17];
      DAT_803de1a8[0x1a] = DAT_803de1a8[0x19];
      DAT_803de1a8[0x14] = DAT_803de1a8[0x13];
      DAT_803de1a8[0x16] = DAT_803de1a8[0x15];
      *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0x3c;
      *(undefined2 *)(DAT_803de1a8 + 0x21) = 0x3c;
    }
    else {
      DAT_803de1a8[0x25] = FLOAT_803e2370;
      dVar4 = DOUBLE_803e2378;
      uStack_2c = (uint)*(byte *)(param_3 + 6);
      local_30 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2378);
      DAT_803de1a8[0x26] = fVar2;
      DAT_803de1a8[0x10] = fVar2;
      uStack_34 = (uint)*(byte *)(param_3 + 8);
      local_38 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
      DAT_803de1a8[0x27] = fVar2;
      DAT_803de1a8[0x12] = fVar2;
      uStack_3c = (uint)*(byte *)(param_3 + 3);
      local_40 = 0x43300000;
      DAT_803de1a8[0xc] = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
      uStack_44 = (uint)*(byte *)(param_3 + 4);
      local_48 = 0x43300000;
      DAT_803de1a8[0xe] = (float)((double)CONCAT44(0x43300000,uStack_44) - dVar4);
      uStack_24 = (int)*(char *)(param_3 + 2) ^ 0x80000000;
      local_28 = 0x43300000;
      DAT_803de1a8[0x1c] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2318);
      uStack_1c = (uint)*(byte *)(param_3 + 9);
      local_20 = 0x43300000;
      DAT_803de1a8[0x18] = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar4);
      uStack_14 = (uint)*(byte *)(param_3 + 10);
      DAT_803de1a8[0x1a] = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar4);
      uVar5 = (uint)*(byte *)(param_3 + 0xb);
      if (uVar5 == 0) {
        DAT_803de1a8[0x14] = FLOAT_803e2394;
      }
      else {
        DAT_803de1a8[0x14] = (float)((double)CONCAT44(0x43300000,uVar5) - dVar4) / FLOAT_803e2390;
        uStack_14 = uVar5;
      }
      uVar5 = (uint)*(byte *)(param_3 + 0xc);
      if (uVar5 == 0) {
        DAT_803de1a8[0x16] = FLOAT_803e2394;
      }
      else {
        DAT_803de1a8[0x16] =
             (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e2378) / FLOAT_803e2390;
        uStack_14 = uVar5;
      }
      local_18 = 0x43300000;
      *(short *)((int)DAT_803de1a8 + 0x82) = (short)*(char *)(param_3 + 1);
      *(short *)(DAT_803de1a8 + 0x21) = (short)*(char *)(param_3 + 1);
      *(undefined *)((int)param_1 + 0x13b) = *(undefined *)(param_3 + 7);
    }
    DAT_803de1a8[0x24] = DAT_803de1a8[0x23];
    DAT_803de1a8[0xf] = DAT_803de1a8[2];
    DAT_803de1a8[0x11] = DAT_803de1a8[3];
    DAT_803de1a8[0xb] = *DAT_803de1a8;
    DAT_803de1a8[0xd] = DAT_803de1a8[1];
    DAT_803de1a8[0x1b] = *(float *)(param_1 + 0x5a);
    DAT_803de1a8[0x17] = DAT_803de1a8[6];
    DAT_803de1a8[0x19] = DAT_803de1a8[7];
    DAT_803de1a8[0x13] = DAT_803de1a8[4];
    DAT_803de1a8[0x15] = DAT_803de1a8[5];
    if ((param_3 != 0) && (*(char *)(param_3 + 0xd) != '\0')) {
      FUN_801039a4((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
      FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                   (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                   (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
      *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0;
    }
  }
  else if (param_2 < 2) {
    if (param_2 == 0) {
      FUN_800033a8((int)DAT_803de1a8,0,0xcc);
      dVar4 = DOUBLE_803e2378;
      if (param_3 != 0) {
        uStack_44 = (uint)*(ushort *)(param_3 + 0x1c);
        local_48 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2378);
        *DAT_803de1a8 = fVar2;
        DAT_803de1a8[0xc] = fVar2;
        uStack_3c = (uint)*(ushort *)(param_3 + 0x1a);
        local_40 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4);
        DAT_803de1a8[1] = fVar2;
        DAT_803de1a8[0xe] = fVar2;
        uStack_34 = (uint)*(byte *)(param_3 + 0x1f);
        local_38 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar4);
        DAT_803de1a8[0x26] = fVar2;
        DAT_803de1a8[2] = fVar2;
        DAT_803de1a8[0x10] = fVar2;
        uStack_2c = (uint)*(byte *)(param_3 + 0x1f);
        local_30 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4);
        DAT_803de1a8[0x27] = fVar2;
        DAT_803de1a8[3] = fVar2;
        DAT_803de1a8[0x12] = fVar2;
      }
      fVar2 = FLOAT_803e2370;
      DAT_803de1a8[0x23] = FLOAT_803e2370;
      DAT_803de1a8[0x25] = fVar2;
      fVar2 = FLOAT_803e2394;
      DAT_803de1a8[4] = FLOAT_803e2394;
      DAT_803de1a8[0x14] = fVar2;
      fVar2 = FLOAT_803e23b4;
      DAT_803de1a8[0x15] = FLOAT_803e23b4;
      DAT_803de1a8[5] = fVar2;
      DAT_803de1a8[0x16] = fVar2;
      fVar2 = FLOAT_803e23b8;
      DAT_803de1a8[6] = FLOAT_803e23b8;
      DAT_803de1a8[0x18] = fVar2;
      fVar2 = FLOAT_803e235c;
      DAT_803de1a8[7] = FLOAT_803e235c;
      DAT_803de1a8[0x1a] = fVar2;
      DAT_803de1a8[9] = FLOAT_803e2350;
      DAT_803de1a8[8] = FLOAT_803e2354;
      *(undefined *)((int)DAT_803de1a8 + 0xc1) = 1;
      DAT_803de1a8[0x1c] = *(float *)(param_1 + 0x5a);
      FUN_801039a4((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
      uVar3 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 6) = uVar3;
      *(undefined4 *)(param_1 + 0x5c) = uVar3;
      *(undefined4 *)(param_1 + 0x54) = uVar3;
      uVar3 = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 8) = uVar3;
      *(undefined4 *)(param_1 + 0x5e) = uVar3;
      *(undefined4 *)(param_1 + 0x56) = uVar3;
      uVar3 = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(param_1 + 10) = uVar3;
      *(undefined4 *)(param_1 + 0x60) = uVar3;
      *(undefined4 *)(param_1 + 0x58) = uVar3;
      *param_1 = 0;
      param_1[2] = 0;
      if (param_3 != 0) {
        *(float *)(param_1 + 0x5a) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x19)) - DOUBLE_803e2378)
        ;
      }
    }
    else if (-1 < param_2) {
      *(float *)(param_1 + 0x5a) = DAT_803de1a8[0x1c];
      *(byte *)((int)DAT_803de1a8 + 0xc6) =
           (byte)((*(byte *)((int)DAT_803de1a8 + 0xc6) >> 6 & 1) << 7) |
           *(byte *)((int)DAT_803de1a8 + 0xc6) & 0x7f;
    }
  }
  else if (param_2 == 4) {
    FUN_801039a4((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)DAT_803de1a8[0x23],param_1,auStack_4c,&local_50,auStack_54,local_58,0);
    local_50 = *(float *)(param_1 + 8) - (*(float *)(psVar7 + 8) + DAT_803de1a8[0x23]);
    iVar6 = FUN_80021884();
    param_1[1] = (short)iVar6;
    param_1[2] = 0;
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 0x5a) = DAT_803de1a8[0x1c];
    *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0;
  }
  else if (param_2 < 4) {
    *(float *)(param_1 + 0x5a) = DAT_803de1a8[0x1c];
    *(float *)(param_1 + 0xc) = DAT_803de1a8[0x1d];
    *(float *)(param_1 + 0xe) = DAT_803de1a8[0x1e];
    *(float *)(param_1 + 0x10) = DAT_803de1a8[0x1f];
    FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
    *param_1 = *(undefined2 *)((int)DAT_803de1a8 + 0x86);
    param_1[1] = *(undefined2 *)(DAT_803de1a8 + 0x22);
    param_1[2] = *(undefined2 *)((int)DAT_803de1a8 + 0x8a);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0;
  }
  *(byte *)((int)DAT_803de1a8 + 0xc6) = *(byte *)((int)DAT_803de1a8 + 0xc6) & 0xbf;
  *(undefined *)(param_1 + 0x9f) = 1;
  return;
}

