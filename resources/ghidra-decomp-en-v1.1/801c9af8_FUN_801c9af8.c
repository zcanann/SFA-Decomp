// Function: FUN_801c9af8
// Entry: 801c9af8
// Size: 276 bytes

void FUN_801c9af8(undefined2 *param_1)

{
  char cVar2;
  int *piVar1;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801c9470;
  *param_1 = 0;
  *(undefined *)(piVar3 + 5) = 0;
  *(byte *)((int)piVar3 + 0x15) = *(byte *)((int)piVar3 + 0x15) & 0x7f;
  *(undefined2 *)(piVar3 + 3) = 0;
  FUN_80037a5c((int)param_1,4);
  FUN_800201ac(0x15f,0);
  cVar2 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_1 + 0x56),1);
  if (cVar2 == '\0') {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_1 + 0x56),1,1);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar3 == 0) {
    piVar1 = FUN_8001f58c(0,'\x01');
    *piVar3 = (int)piVar1;
  }
  FUN_800201ac(0xefa,1);
  FUN_800201ac(0xf08,1);
  return;
}

