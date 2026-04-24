// Function: FUN_80105e7c
// Entry: 80105e7c
// Size: 1904 bytes

void FUN_80105e7c(undefined2 *param_1,int param_2,int param_3)

{
  float *pfVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  uint uVar5;
  undefined2 uVar6;
  int iVar7;
  float local_58;
  undefined auStack84 [4];
  float local_50;
  undefined auStack76 [4];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  *(byte *)((int)DAT_803dd530 + 0xc6) = *(byte *)((int)DAT_803dd530 + 0xc6) & 0x7f;
  *(undefined *)(DAT_803dd530 + 0x31) = 0;
  *(undefined *)((int)DAT_803dd530 + 0xc3) = 0;
  *(undefined *)((int)DAT_803dd530 + 199) = 0;
  *(byte *)(DAT_803dd530 + 0x32) = *(byte *)(DAT_803dd530 + 0x32) & 0x7f;
  *(undefined *)((int)DAT_803dd530 + 0xc2) = 8;
  iVar7 = *(int *)(param_1 + 0x52);
  if (param_2 == 2) {
    if (param_3 == 0) {
      DAT_803dd530[0x25] = DAT_803dd530[0x24];
      pfVar1 = DAT_803dd530 + 0xf;
      DAT_803dd530[0x26] = *pfVar1;
      DAT_803dd530[0x10] = *pfVar1;
      pfVar1 = DAT_803dd530 + 0x11;
      DAT_803dd530[0x27] = *pfVar1;
      DAT_803dd530[0x12] = *pfVar1;
      DAT_803dd530[0xc] = DAT_803dd530[0xb];
      DAT_803dd530[0xe] = DAT_803dd530[0xd];
      DAT_803dd530[0x1c] = DAT_803dd530[0x1b];
      DAT_803dd530[0x18] = DAT_803dd530[0x17];
      DAT_803dd530[0x1a] = DAT_803dd530[0x19];
      DAT_803dd530[0x14] = DAT_803dd530[0x13];
      DAT_803dd530[0x16] = DAT_803dd530[0x15];
      *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0x3c;
      *(undefined2 *)(DAT_803dd530 + 0x21) = 0x3c;
    }
    else {
      DAT_803dd530[0x25] = FLOAT_803e16f0;
      dVar4 = DOUBLE_803e16f8;
      uStack44 = (uint)*(byte *)(param_3 + 6);
      local_30 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e16f8);
      DAT_803dd530[0x26] = fVar2;
      DAT_803dd530[0x10] = fVar2;
      uStack52 = (uint)*(byte *)(param_3 + 8);
      local_38 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar4);
      DAT_803dd530[0x27] = fVar2;
      DAT_803dd530[0x12] = fVar2;
      uStack60 = (uint)*(byte *)(param_3 + 3);
      local_40 = 0x43300000;
      DAT_803dd530[0xc] = (float)((double)CONCAT44(0x43300000,uStack60) - dVar4);
      uStack68 = (uint)*(byte *)(param_3 + 4);
      local_48 = 0x43300000;
      DAT_803dd530[0xe] = (float)((double)CONCAT44(0x43300000,uStack68) - dVar4);
      uStack36 = (int)*(char *)(param_3 + 2) ^ 0x80000000;
      local_28 = 0x43300000;
      DAT_803dd530[0x1c] = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e1698);
      uStack28 = (uint)*(byte *)(param_3 + 9);
      local_20 = 0x43300000;
      DAT_803dd530[0x18] = (float)((double)CONCAT44(0x43300000,uStack28) - dVar4);
      uStack20 = (uint)*(byte *)(param_3 + 10);
      DAT_803dd530[0x1a] = (float)((double)CONCAT44(0x43300000,uStack20) - dVar4);
      uVar5 = (uint)*(byte *)(param_3 + 0xb);
      if (uVar5 == 0) {
        DAT_803dd530[0x14] = FLOAT_803e1714;
      }
      else {
        DAT_803dd530[0x14] = (float)((double)CONCAT44(0x43300000,uVar5) - dVar4) / FLOAT_803e1710;
        uStack20 = uVar5;
      }
      uVar5 = (uint)*(byte *)(param_3 + 0xc);
      if (uVar5 == 0) {
        DAT_803dd530[0x16] = FLOAT_803e1714;
      }
      else {
        DAT_803dd530[0x16] =
             (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e16f8) / FLOAT_803e1710;
        uStack20 = uVar5;
      }
      local_18 = 0x43300000;
      *(short *)((int)DAT_803dd530 + 0x82) = (short)*(char *)(param_3 + 1);
      *(short *)(DAT_803dd530 + 0x21) = (short)*(char *)(param_3 + 1);
      *(undefined *)((int)param_1 + 0x13b) = *(undefined *)(param_3 + 7);
    }
    DAT_803dd530[0x24] = DAT_803dd530[0x23];
    DAT_803dd530[0xf] = DAT_803dd530[2];
    DAT_803dd530[0x11] = DAT_803dd530[3];
    DAT_803dd530[0xb] = *DAT_803dd530;
    DAT_803dd530[0xd] = DAT_803dd530[1];
    DAT_803dd530[0x1b] = *(float *)(param_1 + 0x5a);
    DAT_803dd530[0x17] = DAT_803dd530[6];
    DAT_803dd530[0x19] = DAT_803dd530[7];
    DAT_803dd530[0x13] = DAT_803dd530[4];
    DAT_803dd530[0x15] = DAT_803dd530[5];
    if ((param_3 != 0) && (*(char *)(param_3 + 0xd) != '\0')) {
      FUN_80103708(param_1,iVar7,param_1 + 0xc,param_1 + 1);
      FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                   (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                   *(undefined4 *)(param_1 + 0x18));
      *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0;
    }
  }
  else if (param_2 < 2) {
    if (param_2 == 0) {
      FUN_800033a8(DAT_803dd530,0,0xcc);
      dVar4 = DOUBLE_803e16f8;
      if (param_3 != 0) {
        uStack68 = (uint)*(ushort *)(param_3 + 0x1c);
        local_48 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e16f8);
        *DAT_803dd530 = fVar2;
        DAT_803dd530[0xc] = fVar2;
        uStack60 = (uint)*(ushort *)(param_3 + 0x1a);
        local_40 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack60) - dVar4);
        DAT_803dd530[1] = fVar2;
        DAT_803dd530[0xe] = fVar2;
        uStack52 = (uint)*(byte *)(param_3 + 0x1f);
        local_38 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack52) - dVar4);
        DAT_803dd530[0x26] = fVar2;
        DAT_803dd530[2] = fVar2;
        DAT_803dd530[0x10] = fVar2;
        uStack44 = (uint)*(byte *)(param_3 + 0x1f);
        local_30 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uStack44) - dVar4);
        DAT_803dd530[0x27] = fVar2;
        DAT_803dd530[3] = fVar2;
        DAT_803dd530[0x12] = fVar2;
      }
      fVar2 = FLOAT_803e16f0;
      DAT_803dd530[0x23] = FLOAT_803e16f0;
      DAT_803dd530[0x25] = fVar2;
      fVar2 = FLOAT_803e1714;
      DAT_803dd530[4] = FLOAT_803e1714;
      DAT_803dd530[0x14] = fVar2;
      fVar2 = FLOAT_803e1734;
      DAT_803dd530[0x15] = FLOAT_803e1734;
      DAT_803dd530[5] = fVar2;
      DAT_803dd530[0x16] = fVar2;
      fVar2 = FLOAT_803e1738;
      DAT_803dd530[6] = FLOAT_803e1738;
      DAT_803dd530[0x18] = fVar2;
      fVar2 = FLOAT_803e16dc;
      DAT_803dd530[7] = FLOAT_803e16dc;
      DAT_803dd530[0x1a] = fVar2;
      DAT_803dd530[9] = FLOAT_803e16d0;
      DAT_803dd530[8] = FLOAT_803e16d4;
      *(undefined *)((int)DAT_803dd530 + 0xc1) = 1;
      DAT_803dd530[0x1c] = *(float *)(param_1 + 0x5a);
      FUN_80103708(param_1,iVar7,param_1 + 0xc,param_1 + 1);
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
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x19)) - DOUBLE_803e16f8)
        ;
      }
    }
    else if (-1 < param_2) {
      *(float *)(param_1 + 0x5a) = DAT_803dd530[0x1c];
      *(byte *)((int)DAT_803dd530 + 0xc6) =
           (byte)((*(byte *)((int)DAT_803dd530 + 0xc6) >> 6 & 1) << 7) |
           *(byte *)((int)DAT_803dd530 + 0xc6) & 0x7f;
    }
  }
  else if (param_2 == 4) {
    FUN_80103708(param_1,iVar7,param_1 + 0xc,param_1 + 1);
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
    (**(code **)(*DAT_803dca50 + 0x38))
              ((double)DAT_803dd530[0x23],param_1,auStack76,&local_50,auStack84,&local_58,0);
    local_50 = *(float *)(param_1 + 8) - (*(float *)(iVar7 + 0x10) + DAT_803dd530[0x23]);
    uVar6 = FUN_800217c0((double)local_50,(double)local_58);
    param_1[1] = uVar6;
    param_1[2] = 0;
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 0x5a) = DAT_803dd530[0x1c];
    *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0;
  }
  else if (param_2 < 4) {
    *(float *)(param_1 + 0x5a) = DAT_803dd530[0x1c];
    *(float *)(param_1 + 0xc) = DAT_803dd530[0x1d];
    *(float *)(param_1 + 0xe) = DAT_803dd530[0x1e];
    *(float *)(param_1 + 0x10) = DAT_803dd530[0x1f];
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
    *param_1 = *(undefined2 *)((int)DAT_803dd530 + 0x86);
    param_1[1] = *(undefined2 *)(DAT_803dd530 + 0x22);
    param_1[2] = *(undefined2 *)((int)DAT_803dd530 + 0x8a);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0;
  }
  *(byte *)((int)DAT_803dd530 + 0xc6) = *(byte *)((int)DAT_803dd530 + 0xc6) & 0xbf;
  *(undefined *)(param_1 + 0x9f) = 1;
  return;
}

