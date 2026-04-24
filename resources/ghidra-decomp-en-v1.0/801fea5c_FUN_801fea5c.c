// Function: FUN_801fea5c
// Entry: 801fea5c
// Size: 212 bytes

void FUN_801fea5c(int param_1)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = FUN_8003687c(param_1,0,0,0);
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((iVar2 == 0x12) && (*(char *)(iVar3 + 0x118) != '\x04')) {
    FUN_8002b9ec();
  }
  if (*(char *)(iVar3 + 0x118) != '\t') {
    iVar2 = FUN_800640cc((double)FLOAT_803e6218,param_1 + 0x80,param_1 + 0xc,1,0,param_1,8,
                         0xffffffff,0xff,0);
    fVar1 = FLOAT_803e621c;
    if (iVar2 != 0) {
      *(float *)(param_1 + 0x24) =
           -(FLOAT_803e621c * *(float *)(param_1 + 0x24) - *(float *)(param_1 + 0x24));
      *(float *)(param_1 + 0x2c) =
           -(fVar1 * *(float *)(param_1 + 0x2c) - *(float *)(param_1 + 0x2c));
    }
  }
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  return;
}

