// Function: FUN_80202a60
// Entry: 80202a60
// Size: 252 bytes

undefined4
FUN_80202a60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar1 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f8c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  iVar2 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 2;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 1;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar2 + 0x34) = 1;
  }
  return 0;
}

