// Function: FUN_801e8090
// Entry: 801e8090
// Size: 324 bytes

void FUN_801e8090(int param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined2 uVar3;
  int iVar4;
  float local_18 [3];
  
  uVar1 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  local_18[0] = FLOAT_803e5a20;
  *(byte *)(iVar4 + 0x9d4) = *(byte *)(iVar4 + 0x9d4) & 0xdf;
  if (FLOAT_803e59dc < *(float *)(iVar4 + 0x9c4)) {
    FUN_80016870(0x433);
    *(float *)(iVar4 + 0x9c4) = *(float *)(iVar4 + 0x9c4) - FLOAT_803db414;
    if (*(float *)(iVar4 + 0x9c4) < FLOAT_803e59dc) {
      *(float *)(iVar4 + 0x9c4) = FLOAT_803e59dc;
    }
  }
  if ((*(byte *)(iVar4 + 0x9d4) & 4) != 0) {
    FUN_801e7c4c(param_1,uVar1,1);
  }
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x50) + 4);
  if (*(int *)(iVar4 + 0x9b4) == 0) {
    uVar2 = FUN_80036e58(9,param_1,local_18);
    *(undefined4 *)(iVar4 + 0x9b4) = uVar2;
  }
  uVar3 = FUN_8029689c(uVar1);
  *(undefined2 *)(iVar4 + 0x9c8) = uVar3;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,iVar4,&DAT_803ad068,&DAT_803ddc58
            );
  FUN_80115094(param_1,iVar4 + 0x35c);
  FUN_8003b310(param_1,iVar4 + 0x980);
  *(undefined *)(param_1 + 0x36) = *(undefined *)(iVar4 + 0x9d6);
  return;
}

