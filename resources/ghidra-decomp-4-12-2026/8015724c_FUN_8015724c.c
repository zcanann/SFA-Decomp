// Function: FUN_8015724c
// Entry: 8015724c
// Size: 612 bytes

void FUN_8015724c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)

{
  bool bVar1;
  float fVar2;
  uint uVar3;
  undefined4 in_r8;
  uint uVar4;
  undefined4 in_r9;
  undefined4 uVar5;
  undefined4 in_r10;
  undefined4 uVar6;
  double dVar7;
  float local_90;
  float local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  float local_7c;
  float local_78;
  float local_74;
  int aiStack_70 [22];
  undefined4 local_18;
  uint uStack_14;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
  if (*(float *)(param_10 + 0x324) <= FLOAT_803e37b0) {
    uStack_14 = FUN_80022264(0x3c,0x78);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_10 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e37b8)
    ;
  }
  if (FLOAT_803e37b0 == *(float *)(param_10 + 0x328)) {
    bVar1 = false;
  }
  else {
    FUN_80035ff8((int)param_9);
    if (param_9[0x50] == 5) {
      if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
        FUN_80036018((int)param_9);
        *(float *)(param_10 + 0x328) = FLOAT_803e37b0;
      }
    }
    else {
      FUN_8014d504((double)FLOAT_803dc954,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,5,0,0,in_r8,in_r9,in_r10);
    }
    *(undefined *)(param_9 + 0x1b) = 0xff;
    bVar1 = true;
  }
  if (!bVar1) {
    *param_9 = *param_9 + *(short *)(param_10 + 0x338);
    local_88 = *(undefined4 *)(param_9 + 6);
    local_84 = *(undefined4 *)(param_9 + 8);
    local_80 = *(undefined4 *)(param_9 + 10);
    FUN_80293580((uint)*param_9,&local_90,&local_8c);
    dVar7 = (double)FLOAT_803e37d0;
    local_7c = -(float)(dVar7 * (double)local_90 - (double)*(float *)(param_9 + 6));
    local_78 = FLOAT_803e37d4 + *(float *)(param_9 + 8);
    local_74 = -(float)(dVar7 * (double)local_8c - (double)*(float *)(param_9 + 10));
    uVar4 = (uint)*(byte *)(param_10 + 0x261);
    uVar5 = 0xffffffff;
    uVar6 = 0xff;
    uVar3 = FUN_80064248(&local_88,&local_7c,(float *)0x3,aiStack_70,(int *)param_9,uVar4,0xffffffff
                         ,0xff,0);
    uVar3 = countLeadingZeros(uVar3 & 0xff);
    uVar3 = uVar3 >> 5 & 0xff;
    if ((uVar3 == 0) || ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0)) {
      if ((uVar3 == 0) || (param_9[0x50] == 0)) {
        FUN_8014d504((double)FLOAT_803e37dc,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,1,0,0,uVar4,uVar5,uVar6);
        fVar2 = FLOAT_803e37b0;
        *(float *)(param_9 + 0x12) = FLOAT_803e37b0;
        *(float *)(param_9 + 0x14) = fVar2;
        *(float *)(param_9 + 0x16) = fVar2;
        uVar3 = FUN_80022264(0,1);
        *(short *)(param_10 + 0x338) = ((short)uVar3 + -1) * 300;
      }
      else {
        *(undefined2 *)(param_10 + 0x338) = 0;
        FUN_8014d504((double)FLOAT_803e37d8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,0,0,1,uVar4,uVar5,uVar6);
      }
    }
    param_9[1] = *(ushort *)(param_10 + 0x19c);
    param_9[2] = *(ushort *)(param_10 + 0x19e);
  }
  return;
}

