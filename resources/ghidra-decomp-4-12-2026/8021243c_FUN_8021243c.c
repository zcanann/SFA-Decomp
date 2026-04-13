// Function: FUN_8021243c
// Entry: 8021243c
// Size: 168 bytes

void FUN_8021243c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  if (*(int *)(param_9 + 0xf4) == 0) {
    uVar1 = FUN_80088f20(7,'\x01');
    uVar1 = FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,399,0,in_r7,in_r8,in_r9,in_r10);
    uVar1 = FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x18e,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80008cbc(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,400,0
                 ,in_r7,in_r8,in_r9,in_r10);
    FUN_800890e0((double)FLOAT_803e743c,1);
    FUN_800201ac(0x55e,1);
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  DAT_803de9c0 = FUN_80020078(0x572);
  return;
}

