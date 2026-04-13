// Function: FUN_8015e3cc
// Entry: 8015e3cc
// Size: 236 bytes

undefined4
FUN_8015e3cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10)

{
  float fVar1;
  float *pfVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar3;
  
  fVar1 = FLOAT_803e3a60;
  if (*(char *)(param_10 + 0x27b) == '\0') {
    if (*(char *)(param_10 + 0x346) != '\0') {
      uVar3 = FUN_800377d0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,
                           param_9,0xe0000,param_9,in_r8,in_r9,in_r10);
      if (*(int *)(param_9 + 0x4c) == 0) {
        FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        return 0;
      }
      return 4;
    }
  }
  else {
    pfVar2 = *(float **)(*(int *)(param_9 + 0xb8) + 0x40c);
    *pfVar2 = FLOAT_803e3a60;
    pfVar2[1] = fVar1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_10,6);
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    *(undefined *)(param_10 + 0x25f) = 0;
    *(undefined *)(param_10 + 0x349) = 0;
    FUN_80035ff8(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  return 0;
}

