// Function: FUN_80157a04
// Entry: 80157a04
// Size: 832 bytes

void FUN_80157a04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)

{
  float fVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  double dVar7;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
  if (*(float *)(param_10 + 0x324) <= FLOAT_803e37b0) {
    uVar5 = FUN_80022264(0x3c,0x78);
    *(float *)(param_10 + 0x324) =
         (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e37b8);
  }
  if (FLOAT_803e37b0 == *(float *)(param_10 + 0x328)) {
    bVar3 = false;
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
    bVar3 = true;
  }
  if (!bVar3) {
    dVar7 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x338)) -
                           DOUBLE_803e37f0);
    *param_9 = (ushort)(int)(dVar7 * (double)FLOAT_803dc074 +
                            (double)(float)((double)CONCAT44(0x43300000,
                                                             (int)(short)*param_9 ^ 0x80000000) -
                                           DOUBLE_803e37b8));
    fVar1 = FLOAT_803e37b0;
    *(float *)(param_9 + 0x12) = FLOAT_803e37b0;
    *(float *)(param_9 + 0x14) = fVar1;
    *(float *)(param_9 + 0x16) = fVar1;
    FUN_80035eec((int)param_9,9,1,-1);
    dVar6 = (double)(*(float *)(param_9 + 10) - *(float *)(*(int *)(param_10 + 0x29c) + 0x14));
    uVar5 = FUN_80021884();
    fVar1 = (float)((double)CONCAT44(0x43300000,(uVar5 & 0xffff) - (uint)*param_9 ^ 0x80000000) -
                   DOUBLE_803e37b8);
    if (FLOAT_803e37c4 < fVar1) {
      fVar1 = FLOAT_803e37c0 + fVar1;
    }
    if (fVar1 < FLOAT_803e37cc) {
      fVar1 = FLOAT_803e37c8 + fVar1;
    }
    uVar5 = (uint)(short)(int)fVar1;
    if ((int)uVar5 < 0) {
      uVar5 = -uVar5;
    }
    FUN_80036018((int)param_9);
    uVar4 = *(uint *)(param_10 + 0x2dc) & 0x40000000;
    if ((uVar4 == 0) || (param_9[0x50] != 6)) {
      if ((uVar4 != 0) ||
         (((((uVar5 & 0xffff) < 1000 && (uVar2 = param_9[0x50], uVar2 != 2)) && (uVar2 != 4)) &&
          (uVar2 != 6)))) {
        if ((uVar5 & 0xffff) < 1000) {
          if (FLOAT_803e37f8 <= *(float *)(param_10 + 0x2ac)) {
            FUN_8014d504((double)FLOAT_803dc94c,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,param_10,6,0,0,in_r8,in_r9,in_r10);
          }
          else {
            FUN_8014d504((double)FLOAT_803e37dc,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
          }
          *(undefined2 *)(param_10 + 0x338) = 0;
        }
        else {
          FUN_8014d504((double)FLOAT_803e37dc,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                       (int)param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
          if ((short)(int)fVar1 < 0) {
            *(undefined2 *)(param_10 + 0x338) = 0xfed4;
          }
          else {
            *(undefined2 *)(param_10 + 0x338) = 300;
          }
        }
      }
      param_9[1] = *(ushort *)(param_10 + 0x19c);
      param_9[2] = *(ushort *)(param_10 + 0x19e);
    }
    else {
      FUN_8014d504((double)FLOAT_803dc948,dVar6,dVar7,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,4,0,1,in_r8,in_r9,in_r10);
    }
  }
  return;
}

