// Function: FUN_801c9544
// Entry: 801c9544
// Size: 276 bytes

void FUN_801c9544(undefined2 *param_1)

{
  char cVar2;
  int iVar1;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801c8ebc;
  *param_1 = 0;
  *(undefined *)(piVar3 + 5) = 0;
  *(byte *)((int)piVar3 + 0x15) = *(byte *)((int)piVar3 + 0x15) & 0x7f;
  *(undefined2 *)(piVar3 + 3) = 0;
  FUN_80037964(param_1,4);
  FUN_800200e8(0x15f,0);
  cVar2 = (**(code **)(*DAT_803dcaac + 0x4c))((int)*(char *)(param_1 + 0x56),1);
  if (cVar2 == '\0') {
    (**(code **)(*DAT_803dcaac + 0x50))((int)*(char *)(param_1 + 0x56),1,1);
  }
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar3 == 0) {
    iVar1 = FUN_8001f4c8(0,1);
    *piVar3 = iVar1;
  }
  FUN_800200e8(0xefa,1);
  FUN_800200e8(0xf08,1);
  return;
}

