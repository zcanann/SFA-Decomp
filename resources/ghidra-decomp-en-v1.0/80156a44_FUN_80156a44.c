// Function: FUN_80156a44
// Entry: 80156a44
// Size: 200 bytes

void FUN_80156a44(int param_1,int param_2,undefined4 param_3,int param_4)

{
  short sVar1;
  
  if (param_4 != 0x11) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      sVar1 = *(short *)(param_1 + 0xa0);
      if ((((sVar1 == 0) || (sVar1 == 1)) || (sVar1 == 3)) || (sVar1 == 4)) {
        FUN_8000bb18(param_1,0x250);
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
      }
      else {
        FUN_8014d08c((double)FLOAT_803e2b04,param_1,param_2,4,0,0);
        *(undefined *)(param_2 + 0x33a) = 0;
        FUN_8000bb18(param_1,0x24f);
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      }
    }
  }
  return;
}

