// Function: FUN_80096b50
// Entry: 80096b50
// Size: 208 bytes

void FUN_80096b50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  uVar2 = 0x13;
  uVar3 = 0;
  iVar1 = FUN_80023d8c(0x22b0,0x13);
  if (iVar1 == 0) {
    FUN_80137c30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_Could_not_allocate_memory_for_wa_8031042c,uVar2,uVar3,in_r6,in_r7,in_r8,in_r9,
                 in_r10);
  }
  else {
    DAT_803ddec0 = iVar1 + 0x3c0;
    DAT_803ddecc = iVar1 + 0x780;
    DAT_803ddec4 = iVar1 + 0xf00;
    DAT_803ddeb8 = iVar1 + 0x1680;
    DAT_803ddeb0 = iVar1 + 0x19c8;
    DAT_803ddea0 = iVar1 + 0x1c20;
    DAT_803ddea8 = iVar1 + 0x1f68;
    DAT_803ddebc = 0;
    DAT_803ddeb4 = 0;
    DAT_803ddea4 = 0;
    DAT_803ddeac = 0;
    DAT_803ddec8 = iVar1;
    DAT_803dde9c = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x56
                                ,uVar2,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
    DAT_803dde98 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0xc2a,uVar2,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
    DAT_803dde94 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0xc2c,uVar2,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
    DAT_803dde90 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0xc2d,uVar2,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
    FUN_80096768();
    FUN_80095688();
  }
  return;
}

