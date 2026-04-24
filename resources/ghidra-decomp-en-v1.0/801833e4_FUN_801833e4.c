// Function: FUN_801833e4
// Entry: 801833e4
// Size: 1824 bytes

undefined4 FUN_801833e4(int param_1,int param_2,int param_3)

{
  char cVar4;
  undefined uVar5;
  short *psVar1;
  short sVar3;
  int iVar2;
  double dVar6;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  cVar4 = FUN_8002e04c();
  if (cVar4 != '\0') {
    FUN_800200e8((int)*(short *)(param_3 + 0xe),1);
    switch(*(char *)(param_3 + 0x11)) {
    case '\x01':
      iVar2 = FUN_8002bdf4(0x24,0x3d3);
      *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
      *(undefined2 *)(iVar2 + 0x1a) = 400;
      psVar1 = (short *)FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                                     *(undefined4 *)(param_1 + 0x30));
      *(float *)(psVar1 + 0x12) = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
      *(float *)(psVar1 + 0x16) = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
      if (*(float *)(psVar1 + 0x12) * *(float *)(psVar1 + 0x12) +
          *(float *)(psVar1 + 0x16) * *(float *)(psVar1 + 0x16) != FLOAT_803e39b8) {
        dVar6 = (double)FUN_802931a0();
        *(float *)(psVar1 + 0x12) = (float)((double)*(float *)(psVar1 + 0x12) / dVar6);
        *(float *)(psVar1 + 0x16) = (float)((double)*(float *)(psVar1 + 0x16) / dVar6);
      }
      uStack28 = FUN_800221a0(0,0x19);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar1 + 0x12) =
           *(float *)(psVar1 + 0x12) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      uStack20 = FUN_800221a0(0,0x19);
      local_30 = FLOAT_803e39ac;
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar1 + 0x16) =
           *(float *)(psVar1 + 0x16) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      *(float *)(psVar1 + 0x14) = FLOAT_803e39d8;
      local_2c = FLOAT_803e39b8;
      local_28 = FLOAT_803e39b8;
      local_24 = FLOAT_803e39b8;
      local_34 = 0;
      local_36 = 0;
      local_38 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_38,psVar1 + 0x12);
      sVar3 = FUN_800217c0((double)*(float *)(psVar1 + 0x12),-(double)*(float *)(psVar1 + 0x16));
      iVar2 = (int)*psVar1 - ((int)sVar3 & 0xffffU);
      if (0x8000 < iVar2) {
        iVar2 = iVar2 + -0xffff;
      }
      if (iVar2 < -0x8000) {
        iVar2 = iVar2 + 0xffff;
      }
      *psVar1 = (short)iVar2;
      break;
    case '\x02':
      iVar2 = FUN_8002bdf4(0x24,0x3d4);
      uVar5 = FUN_800221a0(0xffffff81,0x7e);
      *(undefined *)(iVar2 + 0x18) = uVar5;
      *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
      *(undefined2 *)(iVar2 + 0x1a) = 400;
      psVar1 = (short *)FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                                     *(undefined4 *)(param_1 + 0x30));
      *(float *)(psVar1 + 0x12) = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
      *(float *)(psVar1 + 0x16) = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
      if (*(float *)(psVar1 + 0x12) * *(float *)(psVar1 + 0x12) +
          *(float *)(psVar1 + 0x16) * *(float *)(psVar1 + 0x16) != FLOAT_803e39b8) {
        dVar6 = (double)FUN_802931a0();
        *(float *)(psVar1 + 0x12) = (float)((double)*(float *)(psVar1 + 0x12) / dVar6);
        *(float *)(psVar1 + 0x16) = (float)((double)*(float *)(psVar1 + 0x16) / dVar6);
      }
      uStack20 = FUN_800221a0(0,0x19);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar1 + 0x12) =
           *(float *)(psVar1 + 0x12) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      uStack28 = FUN_800221a0(0,0x19);
      local_30 = FLOAT_803e39ac;
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar1 + 0x16) =
           *(float *)(psVar1 + 0x16) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      *(float *)(psVar1 + 0x14) = FLOAT_803e39d8;
      local_2c = FLOAT_803e39b8;
      local_28 = FLOAT_803e39b8;
      local_24 = FLOAT_803e39b8;
      local_34 = 0;
      local_36 = 0;
      local_38 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_38,psVar1 + 0x12);
      sVar3 = FUN_800217c0((double)*(float *)(psVar1 + 0x12),-(double)*(float *)(psVar1 + 0x16));
      iVar2 = (int)*psVar1 - ((int)sVar3 & 0xffffU);
      if (0x8000 < iVar2) {
        iVar2 = iVar2 + -0xffff;
      }
      if (iVar2 < -0x8000) {
        iVar2 = iVar2 + 0xffff;
      }
      *psVar1 = (short)iVar2;
      break;
    case '\x03':
      iVar2 = FUN_8002bdf4(0x24,0x3d5);
      uVar5 = FUN_800221a0(0xffffff81,0x7e);
      *(undefined *)(iVar2 + 0x18) = uVar5;
      *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
      *(undefined2 *)(iVar2 + 0x1a) = 2000;
      psVar1 = (short *)FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                                     *(undefined4 *)(param_1 + 0x30));
      *(float *)(psVar1 + 0x12) = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
      *(float *)(psVar1 + 0x16) = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
      if (*(float *)(psVar1 + 0x12) * *(float *)(psVar1 + 0x12) +
          *(float *)(psVar1 + 0x16) * *(float *)(psVar1 + 0x16) != FLOAT_803e39b8) {
        dVar6 = (double)FUN_802931a0();
        *(float *)(psVar1 + 0x12) = (float)((double)*(float *)(psVar1 + 0x12) / dVar6);
        *(float *)(psVar1 + 0x16) = (float)((double)*(float *)(psVar1 + 0x16) / dVar6);
      }
      uStack20 = FUN_800221a0(0,0x19);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(psVar1 + 0x12) =
           *(float *)(psVar1 + 0x12) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      uStack28 = FUN_800221a0(0,0x19);
      local_30 = FLOAT_803e39ac;
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(psVar1 + 0x16) =
           *(float *)(psVar1 + 0x16) *
           -(FLOAT_803e39d4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e39c8) -
            FLOAT_803e39ac);
      *(float *)(psVar1 + 0x14) = FLOAT_803e39d8;
      local_2c = FLOAT_803e39b8;
      local_28 = FLOAT_803e39b8;
      local_24 = FLOAT_803e39b8;
      local_34 = 0;
      local_36 = 0;
      local_38 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_38,psVar1 + 0x12);
      sVar3 = FUN_800217c0((double)*(float *)(psVar1 + 0x12),-(double)*(float *)(psVar1 + 0x16));
      iVar2 = (int)*psVar1 - ((int)sVar3 & 0xffffU);
      if (0x8000 < iVar2) {
        iVar2 = iVar2 + -0xffff;
      }
      if (iVar2 < -0x8000) {
        iVar2 = iVar2 + 0xffff;
      }
      *psVar1 = (short)iVar2;
      break;
    case '\x05':
    case '\x06':
      if (*(char *)(param_3 + 0x11) == '\x05') {
        iVar2 = FUN_8002bdf4(0x30,0xb);
      }
      else {
        iVar2 = FUN_8002bdf4(0x30,0x3cd);
      }
      *(undefined *)(iVar2 + 0x1a) = 0x14;
      *(undefined2 *)(iVar2 + 0x2c) = 0xffff;
      *(undefined2 *)(iVar2 + 0x1c) = 0xffff;
      *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
      *(float *)(iVar2 + 0xc) = FLOAT_803e39c0 + *(float *)(param_1 + 0x10);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
      *(undefined2 *)(iVar2 + 0x24) = 0xffff;
      iVar2 = FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                           *(undefined4 *)(param_1 + 0x30));
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x2c))
                ((double)FLOAT_803e39b8,(double)FLOAT_803e39ac,(double)FLOAT_803e39b8);
      break;
    case '\a':
    case '\b':
      FUN_800200e8((int)*(short *)(param_3 + 0xe),1);
      break;
    case '\t':
      cVar4 = FUN_8002e04c();
      if (cVar4 != '\0') {
        iVar2 = FUN_8002bdf4(0x24,0x259);
        *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(param_1 + 0xc);
        *(float *)(iVar2 + 0xc) = FLOAT_803e39a8 + *(float *)(param_1 + 0x10);
        *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(param_1 + 0x14);
        *(undefined *)(iVar2 + 4) = 4;
        *(undefined *)(iVar2 + 6) = 200;
        *(undefined2 *)(iVar2 + 0x20) = 0xffff;
        *(undefined2 *)(iVar2 + 0x1a) = 0x7f;
        FUN_8002df90(iVar2,5,(int)*(char *)(param_1 + 0xac),0xffffffff,
                     *(undefined4 *)(param_1 + 0x30));
      }
    }
  }
  return 0;
}

