// Function: FUN_801bdf7c
// Entry: 801bdf7c
// Size: 544 bytes

void FUN_801bdf7c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined auStack56 [4];
  int local_34;
  undefined4 local_30;
  undefined auStack44 [12];
  float local_20;
  undefined4 local_1c;
  float local_18;
  
  iVar1 = FUN_8003687c(param_1,&local_30,&local_34,auStack56);
  if (iVar1 != 0) {
    iVar2 = *(int *)(*(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4) + 0x50) +
            local_34 * 0x10;
    local_20 = FLOAT_803dcdd8 + *(float *)(iVar2 + 4);
    local_1c = *(undefined4 *)(iVar2 + 8);
    local_18 = FLOAT_803dcddc + *(float *)(iVar2 + 0xc);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4b2,auStack44,0x200001,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4b3,auStack44,0x200001,0xffffffff,0);
    FUN_8009a1dc((double)FLOAT_803e4ca4,param_1,auStack44,3,0);
    FUN_8000bb18(param_1,0x18a);
    FUN_80014aa0((double)FLOAT_803e4ca8);
    if (*(char *)(param_2 + 0x354) == '\0') {
      FUN_8000bb18(param_1,0x18c);
    }
    else {
      FUN_8000bb18(param_1,0x18b);
    }
    FUN_8000e67c((double)FLOAT_803e4cac);
    if (FLOAT_803e4c90 == FLOAT_803ddb98) {
      *(undefined *)(param_2 + 0x27a) = 1;
      *(undefined *)(param_2 + 0x346) = 0;
      *(char *)(param_2 + 0x34f) = (char)iVar1;
      *(char *)(param_2 + 0x354) = *(char *)(param_2 + 0x354) + -1;
      DAT_803ddb94 = DAT_803ddb94 + '\x01';
      FUN_800200e8(0x20c,(int)DAT_803ddb94);
      if ((DAT_803ddb94 == '\x03') || (DAT_803ddb94 == '\a')) {
        FLOAT_803ddb98 = FLOAT_803e4cb0;
      }
      else {
        FLOAT_803ddb98 = FLOAT_803e4c90;
      }
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
      *(undefined2 *)(param_2 + 0x270) = 1;
      FUN_800378c4(local_30,0xe0001,param_1,0);
    }
  }
  return;
}

