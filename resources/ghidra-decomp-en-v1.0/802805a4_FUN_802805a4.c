// Function: FUN_802805a4
// Entry: 802805a4
// Size: 544 bytes

void FUN_802805a4(double param_1,double param_2,undefined8 param_3,double param_4,double param_5,
                 int param_6)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  byte *pbVar4;
  byte bVar5;
  undefined4 uVar6;
  double dVar7;
  
  uVar6 = *(undefined4 *)(param_6 + 0x3c);
  if ((*(uint *)(param_6 + 0x10) & 0x100000) == 0) {
    uVar3 = (uint)((double)FLOAT_803e78a0 * param_1);
    if (0x7f < (uVar3 & 0xff)) {
      uVar3 = 0x7f;
    }
    FUN_8027186c(uVar6,7,uVar3);
  }
  else {
    uVar3 = (uint)(FLOAT_803e78a0 * (float)((double)*(float *)(param_6 + 0x4c) * param_1));
    if (0x7f < (uVar3 & 0xff)) {
      uVar3 = 0x7f;
    }
    FUN_8027186c(uVar6,7,uVar3);
  }
  uVar3 = (uint)(FLOAT_803e78b4 * (float)((double)FLOAT_803e78a4 + param_2));
  if (0x7f < (uVar3 & 0xff)) {
    uVar3 = 0x7f;
  }
  FUN_8027186c(uVar6,10,uVar3);
  uVar3 = (uint)(FLOAT_803e78b4 * (float)((double)FLOAT_803e78a4 - param_4));
  if (0x7f < (uVar3 & 0xff)) {
    uVar3 = 0x7f;
  }
  FUN_8027186c(uVar6,0x83,uVar3);
  dVar7 = (double)(float)((double)FLOAT_803e78b8 * param_5);
  uVar3 = FUN_80285fb4(dVar7);
  if (uVar3 < 0x4000) {
    uVar2 = FUN_80285fb4(dVar7);
  }
  else {
    uVar2 = 0x3fff;
  }
  FUN_80271954(uVar6,0x84,uVar2);
  if (*(int *)(param_6 + 0xc) != 0) {
    pbVar4 = *(byte **)(*(int *)(param_6 + 0xc) + 4);
    for (bVar5 = 0; bVar5 < **(byte **)(param_6 + 0xc); bVar5 = bVar5 + 1) {
      bVar1 = *pbVar4;
      if (((bVar1 < 0x40) || (bVar1 == 0x80)) || (bVar1 == 0x84)) {
        FUN_80271954(uVar6,bVar1,*(undefined2 *)(pbVar4 + 2));
      }
      else {
        FUN_8027186c(uVar6,bVar1,pbVar4[2]);
      }
      pbVar4 = pbVar4 + 4;
    }
  }
  return;
}

