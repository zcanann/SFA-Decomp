// Function: FUN_8025e294
// Entry: 8025e294
// Size: 240 bytes

undefined4 FUN_8025e294(undefined4 param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 local_18 [3];
  
  iVar6 = FUN_80253dd0(param_1,0,4);
  if (iVar6 == 0) {
    uVar7 = 0xfffffffd;
  }
  else {
    local_18[0] = 0x83000000;
    uVar7 = FUN_8025327c(param_1,local_18,2,1,0);
    uVar1 = countLeadingZeros(uVar7);
    uVar7 = FUN_80253664(param_1);
    uVar2 = countLeadingZeros(uVar7);
    uVar7 = FUN_8025327c(param_1,param_2,1,0,0);
    uVar3 = countLeadingZeros(uVar7);
    uVar7 = FUN_80253664(param_1);
    uVar4 = countLeadingZeros(uVar7);
    uVar7 = FUN_80253efc(param_1);
    uVar5 = countLeadingZeros(uVar7);
    if ((uVar1 | uVar2 | uVar3 | uVar4 | uVar5) >> 5 == 0) {
      uVar7 = 0;
    }
    else {
      uVar7 = 0xfffffffd;
    }
  }
  return uVar7;
}

