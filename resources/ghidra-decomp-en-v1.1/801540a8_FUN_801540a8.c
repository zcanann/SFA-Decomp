// Function: FUN_801540a8
// Entry: 801540a8
// Size: 148 bytes

void FUN_801540a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) & 0xbf;
  if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) && (*(short *)(param_9 + 0xa0) != 1)) {
    FUN_8000b4f0(param_9,0x49c,2);
    FUN_8014d504((double)FLOAT_803e35a4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
  }
  FUN_80153a08(param_9,param_10);
  return;
}

