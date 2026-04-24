// Function: FUN_80250838
// Entry: 80250838
// Size: 188 bytes

undefined4 FUN_80250838(undefined4 param_1,undefined4 param_2)

{
  ushort uVar1;
  ushort uVar2;
  undefined4 uVar3;
  
  if (DAT_803decb4 == 1) {
    uVar3 = 0x4000;
  }
  else {
    FUN_80243e74();
    DAT_803dec98 = 0;
    FUN_80243ec0(6,&LAB_80250904);
    FUN_802442c4(0x2000000);
    DAT_803deca8 = 0x4000;
    uVar1 = DAT_cc00501a;
    uVar2 = DAT_cc00501a;
    DAT_cc00501a = uVar2 & 0xff | uVar1 & 0xff00;
    DAT_803decac = param_2;
    DAT_803decb0 = param_1;
    FUN_8025097c();
    DAT_803decb4 = 1;
    FUN_80243e9c();
    uVar3 = DAT_803deca8;
  }
  return uVar3;
}

