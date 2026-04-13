// Function: FUN_80088a84
// Entry: 80088a84
// Size: 120 bytes

void FUN_80088a84(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 byte param_9)

{
  undefined4 uVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar2;
  
  DAT_803dddc0 = param_9;
  if ((param_9 & 8) == 0) {
    uVar1 = FUN_8002bac4();
    uVar2 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1
                         ,0x136,0,in_r7,in_r8,in_r9,in_r10);
    uVar2 = FUN_80008cbc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,
                         0x137,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar1,0x143,0,
                 in_r7,in_r8,in_r9,in_r10);
  }
  return;
}

