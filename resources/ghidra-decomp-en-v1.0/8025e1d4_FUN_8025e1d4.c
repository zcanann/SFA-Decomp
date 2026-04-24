// Function: FUN_8025e1d4
// Entry: 8025e1d4
// Size: 192 bytes

undefined4 FUN_8025e1d4(undefined4 param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 local_10 [2];
  
  iVar4 = FUN_80253dd0(param_1,0,4);
  if (iVar4 == 0) {
    uVar5 = 0xfffffffd;
  }
  else {
    if (param_2 == 0) {
      local_10[0] = 0x81000000;
    }
    else {
      local_10[0] = 0x81010000;
    }
    uVar5 = FUN_8025327c(param_1,local_10,2,1,0);
    uVar1 = countLeadingZeros(uVar5);
    uVar5 = FUN_80253664(param_1);
    uVar2 = countLeadingZeros(uVar5);
    uVar5 = FUN_80253efc(param_1);
    uVar3 = countLeadingZeros(uVar5);
    if ((uVar1 | uVar2 | uVar3) >> 5 == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = 0xfffffffd;
    }
  }
  return uVar5;
}

