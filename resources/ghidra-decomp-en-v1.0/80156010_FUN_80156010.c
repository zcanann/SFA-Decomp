// Function: FUN_80156010
// Entry: 80156010
// Size: 376 bytes

void FUN_80156010(int param_1,int param_2)

{
  bool bVar1;
  short sVar2;
  
  *(float *)(param_2 + 0x324) = *(float *)(param_2 + 0x324) - FLOAT_803db414;
  bVar1 = *(float *)(param_2 + 0x324) <= FLOAT_803e2a60;
  if (bVar1) {
    *(float *)(param_2 + 0x324) = FLOAT_803e2a60;
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    sVar2 = *(short *)(param_1 + 0xa0);
    if (sVar2 == 4) {
      FUN_80155b10(param_1,param_2);
      *(float *)(param_2 + 0x324) = FLOAT_803e2a80;
      FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,5,0,0);
    }
    else if ((sVar2 == 5) && (bVar1)) {
      FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,6,0,0);
      FUN_8000bb18(param_1,0x24c);
    }
    else if (sVar2 == 6) {
      FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,2,0,0);
      *(float *)(param_2 + 0x324) = FLOAT_803e2a80;
    }
    else if (((sVar2 == 2) && (bVar1)) && ((*(uint *)(param_2 + 0x2dc) & 0x4000000) != 0)) {
      FUN_8014d08c((double)FLOAT_803e2a54,param_1,param_2,4,0,0);
      FUN_8000bb18(param_1,0x24b);
    }
  }
  FUN_80155cf8(param_1,param_2);
  return;
}

