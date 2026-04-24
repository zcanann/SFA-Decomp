// Function: FUN_80103664
// Entry: 80103664
// Size: 164 bytes

undefined FUN_80103664(undefined4 param_1,int param_2,undefined4 param_3)

{
  undefined4 local_88;
  float local_84;
  undefined4 local_80;
  undefined auStack124 [110];
  undefined local_e;
  
  if (*(short *)(param_2 + 0x44) == 1) {
    FUN_80296bd4(param_2,&local_88,&local_84,&local_80);
  }
  else {
    local_88 = *(undefined4 *)(param_2 + 0x18);
    local_84 = *(float *)(param_2 + 0x1c) + *(float *)(DAT_803dd530 + 0x8c);
    local_80 = *(undefined4 *)(param_2 + 0x20);
  }
  FUN_80103524((double)FLOAT_803e1688,&local_88,param_1,param_3,auStack124,3,1,1);
  return local_e;
}

