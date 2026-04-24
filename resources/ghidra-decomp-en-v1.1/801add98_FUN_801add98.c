// Function: FUN_801add98
// Entry: 801add98
// Size: 332 bytes

void FUN_801add98(undefined2 *param_1,undefined2 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,char param_7,int param_8,int param_9)

{
  undefined uVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20 [5];
  
  if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8)) {
    uVar1 = *(undefined *)((int)param_2 + 0x37);
    *(char *)((int)param_2 + 0x37) = (char)param_8;
    (**(code **)(**(int **)(param_2 + 0x34) + 0x10))
              (param_2,param_3,param_4,param_5,param_6,0xffffffff);
    *(undefined *)((int)param_2 + 0x37) = uVar1;
  }
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  (**(code **)(**(int **)(param_2 + 0x34) + 0x28))(param_2,local_20,&local_24,&local_28);
  *(undefined4 *)(param_1 + 6) = local_20[0];
  *(undefined4 *)(param_1 + 8) = local_24;
  *(undefined4 *)(param_1 + 10) = local_28;
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_2 + 0x12);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_2 + 0x16);
  return;
}

