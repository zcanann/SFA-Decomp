// Function: FUN_80280d08
// Entry: 80280d08
// Size: 544 bytes

void FUN_80280d08(double param_1,double param_2,undefined8 param_3,double param_4,double param_5,
                 int param_6)

{
  byte bVar1;
  uint uVar2;
  byte bVar3;
  byte *pbVar4;
  uint uVar5;
  double dVar6;
  
  uVar5 = *(uint *)(param_6 + 0x3c);
  if ((*(uint *)(param_6 + 0x10) & 0x100000) == 0) {
    if (((int)((double)FLOAT_803e8538 * param_1) & 0xffU) < 0x80) {
      bVar3 = (byte)(int)((double)FLOAT_803e8538 * param_1);
    }
    else {
      bVar3 = 0x7f;
    }
    FUN_80271fd0(uVar5,7,bVar3);
  }
  else {
    uVar2 = (uint)(FLOAT_803e8538 * (float)((double)*(float *)(param_6 + 0x4c) * param_1));
    bVar3 = (byte)uVar2;
    if (0x7f < (uVar2 & 0xff)) {
      bVar3 = 0x7f;
    }
    FUN_80271fd0(uVar5,7,bVar3);
  }
  uVar2 = (uint)(FLOAT_803e854c * (float)((double)FLOAT_803e853c + param_2));
  if ((uVar2 & 0xff) < 0x80) {
    bVar3 = (byte)uVar2;
  }
  else {
    bVar3 = 0x7f;
  }
  FUN_80271fd0(uVar5,10,bVar3);
  uVar2 = (uint)(FLOAT_803e854c * (float)((double)FLOAT_803e853c - param_4));
  if ((uVar2 & 0xff) < 0x80) {
    bVar3 = (byte)uVar2;
  }
  else {
    bVar3 = 0x7f;
  }
  FUN_80271fd0(uVar5,0x83,bVar3);
  dVar6 = (double)(float)((double)FLOAT_803e8550 * param_5);
  uVar2 = FUN_80286718(dVar6);
  if (uVar2 < 0x4000) {
    uVar2 = FUN_80286718(dVar6);
    uVar2 = uVar2 & 0xffff;
  }
  else {
    uVar2 = 0x3fff;
  }
  FUN_802720b8(uVar5,0x84,uVar2);
  if (*(int *)(param_6 + 0xc) != 0) {
    pbVar4 = *(byte **)(*(int *)(param_6 + 0xc) + 4);
    for (bVar3 = 0; bVar3 < **(byte **)(param_6 + 0xc); bVar3 = bVar3 + 1) {
      bVar1 = *pbVar4;
      if (((bVar1 < 0x40) || (bVar1 == 0x80)) || (bVar1 == 0x84)) {
        FUN_802720b8(uVar5,bVar1,(uint)*(ushort *)(pbVar4 + 2));
      }
      else {
        FUN_80271fd0(uVar5,bVar1,pbVar4[2]);
      }
      pbVar4 = pbVar4 + 4;
    }
  }
  return;
}

