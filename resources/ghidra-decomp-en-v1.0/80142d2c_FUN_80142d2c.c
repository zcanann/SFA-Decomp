// Function: FUN_80142d2c
// Entry: 80142d2c
// Size: 388 bytes

bool FUN_80142d2c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  local_28 = DAT_802c21dc;
  local_24 = DAT_802c21e0;
  local_20 = DAT_802c21e4;
  local_1c = DAT_802c21e8;
  local_18 = DAT_802c21ec;
  iVar1 = FUN_8014460c();
  if (iVar1 != 0) {
    *(float *)(param_2 + 0x720) = FLOAT_803e23dc;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffffef;
    *(undefined *)(param_2 + 10) = 0;
    return true;
  }
  iVar1 = (**(code **)(*DAT_803dca68 + 0x24))(&local_28,5);
  if (iVar1 != 2) {
    if (iVar1 < 2) {
      if (iVar1 < 0) goto LAB_80142e44;
    }
    else if (5 < iVar1) goto LAB_80142e44;
    iVar1 = *(int *)(param_1 + 0xb8);
    if (((*(byte *)(iVar1 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
        (iVar2 = FUN_8000b578(param_1,0x10), iVar2 == 0)))) {
      FUN_800393f8(param_1,iVar1 + 0x3a8,0x35d,0x500,0xffffffff,0);
    }
  }
LAB_80142e44:
  if (FLOAT_803e23dc == *(float *)(param_2 + 0x720)) {
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffffef;
    *(undefined *)(param_2 + 10) = 0;
  }
  cVar3 = FUN_8013b368((double)FLOAT_803e2408,param_1,param_2);
  return cVar3 == '\x01';
}

