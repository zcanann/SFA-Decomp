// Function: FUN_801c7f70
// Entry: 801c7f70
// Size: 268 bytes

void FUN_801c7f70(undefined2 *param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c7444;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(piVar2 + 5) = 0;
  *(byte *)((int)piVar2 + 0x15) = *(byte *)((int)piVar2 + 0x15) & 0x7f;
  FUN_800200e8(0x129,1);
  FUN_800200e8(299,0);
  FUN_800200e8(0x149,0);
  FUN_800200e8(0x14c,0);
  FUN_800200e8(0x14d,0);
  FUN_800200e8(0x14e,0);
  FUN_800200e8(0x14a,0);
  FUN_800200e8(0x14b,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar2 == 0) {
    iVar1 = FUN_8001f4c8(0,1);
    *piVar2 = iVar1;
  }
  FUN_800200e8(0xea1,1);
  FUN_800200e8(0xefa,1);
  return;
}

