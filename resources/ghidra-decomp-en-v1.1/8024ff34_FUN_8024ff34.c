// Function: FUN_8024ff34
// Entry: 8024ff34
// Size: 216 bytes

void FUN_8024ff34(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar1 = FUN_8025000c();
  if (param_1 != uVar1) {
    uVar1 = FUN_802501e4();
    if ((uVar1 == 0) && (param_1 == 1)) {
      uVar2 = FUN_8025023c();
      uVar3 = FUN_80250210();
      FUN_80250220(0);
      FUN_802501f4(0);
      FUN_80243e74();
      FUN_80250520();
      uVar1 = DAT_cc006c00;
      DAT_cc006c00 = uVar1 & 0xffffffdf | 0x20;
      uVar1 = DAT_cc006c00;
      DAT_cc006c00 = uVar1 & 0xfffffffe | 1;
      FUN_80243e9c();
      FUN_802501f4(uVar2);
      FUN_80250220(uVar3);
    }
    else {
      uVar1 = DAT_cc006c00;
      DAT_cc006c00 = uVar1 & 0xfffffffe | param_1;
    }
  }
  return;
}

