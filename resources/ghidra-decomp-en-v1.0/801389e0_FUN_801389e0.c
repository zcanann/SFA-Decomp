// Function: FUN_801389e0
// Entry: 801389e0
// Size: 384 bytes

void FUN_801389e0(undefined4 param_1,int param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char local_18 [12];
  
  if (*param_3 != 0) {
    FUN_80037cb0();
    FUN_8002cbc4(*param_3);
    *param_3 = 0;
    local_18[0] = -1;
    local_18[1] = 0xff;
    local_18[2] = 0xff;
    iVar1 = *(int *)(param_2 + 0x7a8);
    if (iVar1 != 0) {
      local_18[*(byte *)(param_2 + 0x7bc) >> 6] = '\x01';
    }
    iVar2 = *(int *)(param_2 + 0x7b0);
    if (iVar2 != 0) {
      local_18[*(byte *)(param_2 + 0x7bc) >> 4 & 3] = '\x01';
    }
    iVar3 = *(int *)(param_2 + 0x7b8);
    if (iVar3 != 0) {
      local_18[*(byte *)(param_2 + 0x7bc) >> 2 & 3] = '\x01';
    }
    if (local_18[0] == -1) {
      if (iVar1 == 0) {
        if (iVar2 == 0) {
          if (iVar3 != 0) {
            FUN_80037cb0(param_1,iVar3);
            FUN_80037d2c(param_1,*(undefined4 *)(param_2 + 0x7b8),0);
            *(byte *)(param_2 + 0x7bc) = *(byte *)(param_2 + 0x7bc) & 0xf3;
          }
        }
        else {
          FUN_80037cb0(param_1,iVar2);
          FUN_80037d2c(param_1,*(undefined4 *)(param_2 + 0x7b0),0);
          *(byte *)(param_2 + 0x7bc) = *(byte *)(param_2 + 0x7bc) & 0xcf;
        }
      }
      else {
        FUN_80037cb0(param_1);
        FUN_80037d2c(param_1,*(undefined4 *)(param_2 + 0x7a8),0);
        *(byte *)(param_2 + 0x7bc) = *(byte *)(param_2 + 0x7bc) & 0x3f;
      }
    }
  }
  return;
}

