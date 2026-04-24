// Function: FUN_801dae90
// Entry: 801dae90
// Size: 276 bytes

void FUN_801dae90(undefined2 *param_1,int param_2)

{
  undefined uVar3;
  int iVar1;
  char cVar4;
  undefined4 uVar2;
  undefined4 *puVar5;
  
  puVar5 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x4000;
  uVar3 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  *(undefined *)(puVar5 + 5) = uVar3;
  if ((*(char *)(puVar5 + 5) == '\0') &&
     (iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x20)), iVar1 != 0)) {
    *(undefined *)(puVar5 + 5) = 2;
  }
  if ((*(char *)(puVar5 + 5) != '\0') && (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
    iVar1 = FUN_8002bdf4(0x20,0x55);
    *(undefined4 *)(iVar1 + 8) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 10);
    *(undefined *)(iVar1 + 4) = 2;
    *(undefined *)(iVar1 + 5) = *(undefined *)(*(int *)(param_1 + 0x26) + 5);
    *(undefined *)(iVar1 + 7) = *(undefined *)(*(int *)(param_1 + 0x26) + 7);
    uVar2 = FUN_8002b5a0(param_1);
    *puVar5 = uVar2;
  }
  *(code **)(param_1 + 0x5e) = FUN_801da954;
  return;
}

