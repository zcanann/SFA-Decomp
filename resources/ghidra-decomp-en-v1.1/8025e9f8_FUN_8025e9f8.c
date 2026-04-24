// Function: FUN_8025e9f8
// Entry: 8025e9f8
// Size: 240 bytes

undefined4 FUN_8025e9f8(int param_1,byte *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  byte local_18 [12];
  
  iVar6 = FUN_80254534(param_1,0,4);
  if (iVar6 == 0) {
    uVar7 = 0xfffffffd;
  }
  else {
    local_18[0] = 0x83;
    local_18[1] = 0;
    local_18[2] = 0;
    local_18[3] = 0;
    uVar7 = FUN_802539e0(param_1,local_18,2,1,0);
    uVar1 = countLeadingZeros(uVar7);
    uVar7 = FUN_80253dc8(param_1);
    uVar2 = countLeadingZeros(uVar7);
    uVar7 = FUN_802539e0(param_1,param_2,1,0,0);
    uVar3 = countLeadingZeros(uVar7);
    uVar7 = FUN_80253dc8(param_1);
    uVar4 = countLeadingZeros(uVar7);
    uVar7 = FUN_80254660(param_1);
    uVar5 = countLeadingZeros(uVar7);
    if ((((uVar1 >> 5 == 0 && uVar2 >> 5 == 0) && uVar3 >> 5 == 0) && uVar4 >> 5 == 0) &&
        uVar5 >> 5 == 0) {
      uVar7 = 0;
    }
    else {
      uVar7 = 0xfffffffd;
    }
  }
  return uVar7;
}

