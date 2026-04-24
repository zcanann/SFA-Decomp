// Function: FUN_801bb038
// Entry: 801bb038
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x801bb11c) */
/* WARNING: Removing unreachable block (ram,0x801bb048) */

undefined4
FUN_801bb038(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,9,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e589c;
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x13,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined2 *)(param_9 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e5870;
    *(float *)(param_10 + 0x280) = FLOAT_803e5870;
    *(float *)(param_10 + 0x284) = fVar1;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_9,param_10,0,1,&DAT_803266e0);
  (**(code **)(*DAT_803dd70c + 0x30))(param_1,param_9,param_10,0xf0);
  return 0;
}

