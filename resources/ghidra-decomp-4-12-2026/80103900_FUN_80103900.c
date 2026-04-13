// Function: FUN_80103900
// Entry: 80103900
// Size: 164 bytes

undefined FUN_80103900(float *param_1,int param_2,float *param_3)

{
  float local_88;
  float local_84;
  undefined4 local_80;
  undefined auStack_7c [110];
  undefined local_e;
  
  if (*(short *)(param_2 + 0x44) == 1) {
    FUN_80297334(param_2,&local_88,&local_84,&local_80);
  }
  else {
    local_88 = *(float *)(param_2 + 0x18);
    local_84 = *(float *)(param_2 + 0x1c) + *(float *)(DAT_803de1a8 + 0x8c);
    local_80 = *(undefined4 *)(param_2 + 0x20);
  }
  FUN_801037c0((double)FLOAT_803e2308,&local_88,param_1,param_3,(int)auStack_7c,3,'\x01','\x01');
  return local_e;
}

