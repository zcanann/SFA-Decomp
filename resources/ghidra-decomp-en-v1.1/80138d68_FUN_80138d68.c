// Function: FUN_80138d68
// Entry: 80138d68
// Size: 384 bytes

void FUN_80138d68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int *param_11)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  char local_18 [12];
  
  if (*param_11 != 0) {
    uVar4 = FUN_80037da8(param_9,*param_11);
    FUN_8002cc9c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*param_11);
    *param_11 = 0;
    local_18[0] = -1;
    local_18[1] = 0xff;
    local_18[2] = 0xff;
    iVar1 = *(int *)(param_10 + 0x7a8);
    if (iVar1 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 6] = '\x01';
    }
    iVar2 = *(int *)(param_10 + 0x7b0);
    if (iVar2 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 4 & 3] = '\x01';
    }
    iVar3 = *(int *)(param_10 + 0x7b8);
    if (iVar3 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 2 & 3] = '\x01';
    }
    if (local_18[0] == -1) {
      if (iVar1 == 0) {
        if (iVar2 == 0) {
          if (iVar3 != 0) {
            FUN_80037da8(param_9,iVar3);
            FUN_80037e24(param_9,*(int *)(param_10 + 0x7b8),0);
            *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xf3;
          }
        }
        else {
          FUN_80037da8(param_9,iVar2);
          FUN_80037e24(param_9,*(int *)(param_10 + 0x7b0),0);
          *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xcf;
        }
      }
      else {
        FUN_80037da8(param_9,iVar1);
        FUN_80037e24(param_9,*(int *)(param_10 + 0x7a8),0);
        *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0x3f;
      }
    }
  }
  return;
}

