// Function: FUN_80103130
// Entry: 80103130
// Size: 116 bytes

int FUN_80103130(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)

{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (param_9 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_80023d8c(0x10,0xf);
    if (iVar1 != 0) {
      FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0xb,
                   (param_9 + -1) * 0x10,0x10,in_r7,in_r8,in_r9,in_r10);
    }
  }
  return iVar1;
}

