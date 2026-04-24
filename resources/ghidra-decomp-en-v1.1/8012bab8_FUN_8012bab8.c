// Function: FUN_8012bab8
// Entry: 8012bab8
// Size: 508 bytes

void FUN_8012bab8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  byte bVar2;
  double dVar3;
  double dVar4;
  undefined8 uVar5;
  double dVar6;
  
  uVar1 = FUN_80014e9c(0);
  dVar6 = (double)FLOAT_803de3e4;
  dVar3 = (double)(float)(dVar6 * (double)FLOAT_803dc074 + (double)FLOAT_803de3e0);
  dVar4 = DOUBLE_803e2df0;
  if (DOUBLE_803e2df0 < dVar3) {
    dVar4 = dVar3;
  }
  dVar3 = DOUBLE_803e2be0;
  if ((double)(float)dVar4 < DOUBLE_803e2be0) {
    dVar3 = (double)(float)dVar4;
  }
  FLOAT_803de3e0 = (float)dVar3;
  if ((((0xb < DAT_803de400) || (DAT_803de400 < 8)) && ((uVar1 & 0x200) != 0)) &&
     (DOUBLE_803e2df0 < dVar6)) {
    uVar5 = FUN_80014b68(0,0x200);
    FLOAT_803de3e4 = FLOAT_803e2df8;
    if (DAT_803de4a4 == &DAT_8031c980) {
      DAT_803de458 = 1;
    }
    DAT_803de49c = 0;
    if (DAT_803de400 == 4) {
      FUN_80022264(0,1);
      FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
      DAT_803de401 = '\x03';
    }
    else if (DAT_803de400 < 4) {
      if (2 < DAT_803de400) {
        FUN_80022264(0,1);
        FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
        DAT_803de401 = '\x02';
      }
    }
    else if (DAT_803de400 < 6) {
      FUN_80022264(0,1);
      FUN_8000d220(uVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8);
      DAT_803de401 = '\x01';
    }
    for (bVar2 = 1; bVar2 < 4; bVar2 = bVar2 + 1) {
      uVar1 = countLeadingZeros((int)DAT_803de401 - (uint)bVar2);
      FUN_8003042c((double)FLOAT_803e2abc,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&DAT_803aa070)[bVar2],uVar1 >> 5,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
  }
  DAT_803de404 = DAT_803de404 + (ushort)DAT_803dc070 * -0x50;
  if (DAT_803de404 < 0) {
    DAT_803de404 = 0;
  }
  FUN_8012c33c();
  return;
}

