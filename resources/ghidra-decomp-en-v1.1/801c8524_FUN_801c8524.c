// Function: FUN_801c8524
// Entry: 801c8524
// Size: 268 bytes

void FUN_801c8524(undefined2 *param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c79f8;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(piVar2 + 5) = 0;
  *(byte *)((int)piVar2 + 0x15) = *(byte *)((int)piVar2 + 0x15) & 0x7f;
  FUN_800201ac(0x129,1);
  FUN_800201ac(299,0);
  FUN_800201ac(0x149,0);
  FUN_800201ac(0x14c,0);
  FUN_800201ac(0x14d,0);
  FUN_800201ac(0x14e,0);
  FUN_800201ac(0x14a,0);
  FUN_800201ac(0x14b,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar2 == 0) {
    piVar1 = FUN_8001f58c(0,'\x01');
    *piVar2 = (int)piVar1;
  }
  FUN_800201ac(0xea1,1);
  FUN_800201ac(0xefa,1);
  return;
}

