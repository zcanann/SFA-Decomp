// Function: FUN_80156da0
// Entry: 80156da0
// Size: 612 bytes

void FUN_80156da0(short *param_1,int param_2)

{
  bool bVar1;
  float fVar2;
  uint uVar3;
  short sVar4;
  float local_90;
  float local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  float local_7c;
  float local_78;
  float local_74;
  undefined auStack112 [88];
  undefined4 local_18;
  uint uStack20;
  
  *(float *)(param_2 + 0x324) = *(float *)(param_2 + 0x324) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x324) <= FLOAT_803e2b18) {
    uStack20 = FUN_800221a0(0x3c,0x78);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_2 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e2b20);
  }
  if (FLOAT_803e2b18 == *(float *)(param_2 + 0x328)) {
    bVar1 = false;
  }
  else {
    FUN_80035f00(param_1);
    if (param_1[0x50] == 5) {
      if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
        FUN_80035f20(param_1);
        *(float *)(param_2 + 0x328) = FLOAT_803e2b18;
      }
    }
    else {
      FUN_8014d08c((double)FLOAT_803dbcec,param_1,param_2,5,0,0);
    }
    *(undefined *)(param_1 + 0x1b) = 0xff;
    bVar1 = true;
  }
  if (!bVar1) {
    *param_1 = *param_1 + *(short *)(param_2 + 0x338);
    local_88 = *(undefined4 *)(param_1 + 6);
    local_84 = *(undefined4 *)(param_1 + 8);
    local_80 = *(undefined4 *)(param_1 + 10);
    FUN_80292e20(*param_1,&local_90,&local_8c);
    local_7c = -(FLOAT_803e2b38 * local_90 - *(float *)(param_1 + 6));
    local_78 = FLOAT_803e2b3c + *(float *)(param_1 + 8);
    local_74 = -(FLOAT_803e2b38 * local_8c - *(float *)(param_1 + 10));
    uVar3 = FUN_800640cc((double)FLOAT_803e2b18,&local_88,&local_7c,3,auStack112,param_1,
                         *(undefined *)(param_2 + 0x261),0xffffffff,0xff,0);
    uVar3 = countLeadingZeros(uVar3 & 0xff);
    uVar3 = uVar3 >> 5 & 0xff;
    if ((uVar3 == 0) || ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0)) {
      if ((uVar3 == 0) || (param_1[0x50] == 0)) {
        FUN_8014d08c((double)FLOAT_803e2b44,param_1,param_2,1,0,0);
        fVar2 = FLOAT_803e2b18;
        *(float *)(param_1 + 0x12) = FLOAT_803e2b18;
        *(float *)(param_1 + 0x14) = fVar2;
        *(float *)(param_1 + 0x16) = fVar2;
        sVar4 = FUN_800221a0(0,1);
        *(short *)(param_2 + 0x338) = (sVar4 + -1) * 300;
      }
      else {
        *(undefined2 *)(param_2 + 0x338) = 0;
        FUN_8014d08c((double)FLOAT_803e2b40,param_1,param_2,0,0,1);
      }
    }
    param_1[1] = *(short *)(param_2 + 0x19c);
    param_1[2] = *(short *)(param_2 + 0x19e);
  }
  return;
}

