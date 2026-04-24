// Function: FUN_8025eae8
// Entry: 8025eae8
// Size: 172 bytes

undefined4 FUN_8025eae8(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  byte local_c [4];
  
  iVar4 = FUN_80254534(param_1,0,4);
  if (iVar4 == 0) {
    uVar5 = 0xfffffffd;
  }
  else {
    local_c[0] = 0x89;
    local_c[1] = 0;
    local_c[2] = 0;
    local_c[3] = 0;
    uVar5 = FUN_802539e0(param_1,local_c,1,1,0);
    uVar1 = countLeadingZeros(uVar5);
    uVar5 = FUN_80253dc8(param_1);
    uVar2 = countLeadingZeros(uVar5);
    uVar5 = FUN_80254660(param_1);
    uVar3 = countLeadingZeros(uVar5);
    if ((uVar1 >> 5 == 0 && uVar2 >> 5 == 0) && uVar3 >> 5 == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = 0xfffffffd;
    }
  }
  return uVar5;
}

