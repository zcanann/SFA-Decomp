// Function: FUN_801b9204
// Entry: 801b9204
// Size: 496 bytes

void FUN_801b9204(undefined2 *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  undefined uVar4;
  undefined2 uVar3;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar5 + 0xa0) = *(undefined4 *)(param_2 + 0x14);
  *(float *)(iVar5 + 0xa4) =
       (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
              DOUBLE_803e4b60) / FLOAT_803e4b48;
  uVar2 = FUN_800221a0(0xffffffe2,0x1e);
  *(float *)(iVar5 + 0xa8) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4b60);
  *(undefined4 *)(param_2 + 0x14) = 0xffffffff;
  uVar4 = FUN_800221a0(0,*(char *)(*(int *)(param_1 + 0x28) + 0x55) + -1);
  *(undefined *)((int)param_1 + 0xad) = uVar4;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar3 = FUN_800221a0(0,0xffff);
  *param_1 = uVar3;
  *(undefined *)(param_1 + 0x1b) = 0;
  sVar1 = param_1[0x23];
  if (sVar1 == 0x10d) {
    uVar2 = FUN_800221a0(0,0x32);
    *(float *)(iVar5 + 0xac) =
         FLOAT_803e4b54 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4b60)
    ;
    *(float *)(iVar5 + 0xb0) = FLOAT_803e4b50;
  }
  else if ((sVar1 < 0x10d) && (sVar1 == 0x109)) {
    uVar2 = FUN_800221a0(0,0x28);
    *(float *)(iVar5 + 0xac) =
         FLOAT_803e4b4c + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4b60)
    ;
    *(float *)(iVar5 + 0xb0) = FLOAT_803e4b50;
  }
  else {
    uVar2 = FUN_800221a0(0,0x28);
    *(float *)(iVar5 + 0xac) =
         FLOAT_803e4b58 + (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4b60)
    ;
    *(float *)(iVar5 + 0xb0) = FLOAT_803e4b50;
  }
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

