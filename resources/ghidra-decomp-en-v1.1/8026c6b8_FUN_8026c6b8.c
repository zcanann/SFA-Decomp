// Function: FUN_8026c6b8
// Entry: 8026c6b8
// Size: 220 bytes

void FUN_8026c6b8(int param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar1 = *(int **)(param_1 + 0xe64);
  if (*(int **)(param_1 + 0xe64) != (int *)0x0) {
    do {
      piVar2 = piVar1;
      piVar1 = (int *)*piVar2;
    } while ((int *)*piVar2 != (int *)0x0);
    if (DAT_803dee9c != 0) {
      *piVar2 = DAT_803dee9c;
      *(int **)(DAT_803dee9c + 4) = piVar2;
    }
    DAT_803dee9c = *(int *)(param_1 + 0xe64);
    *(undefined4 *)(param_1 + 0xe64) = 0;
  }
  piVar1 = *(int **)(param_1 + 0xe68);
  if (*(int **)(param_1 + 0xe68) != (int *)0x0) {
    do {
      piVar2 = piVar1;
      piVar1 = (int *)*piVar2;
    } while ((int *)*piVar2 != (int *)0x0);
    if (DAT_803dee9c != 0) {
      *piVar2 = DAT_803dee9c;
      *(int **)(DAT_803dee9c + 4) = piVar2;
    }
    DAT_803dee9c = *(int *)(param_1 + 0xe68);
    *(undefined4 *)(param_1 + 0xe68) = 0;
  }
  piVar1 = *(int **)(param_1 + 0xe6c);
  if (*(int **)(param_1 + 0xe6c) != (int *)0x0) {
    do {
      piVar2 = piVar1;
      piVar1 = (int *)*piVar2;
    } while ((int *)*piVar2 != (int *)0x0);
    if (DAT_803dee9c != 0) {
      *piVar2 = DAT_803dee9c;
      *(int **)(DAT_803dee9c + 4) = piVar2;
    }
    DAT_803dee9c = *(undefined4 *)(param_1 + 0xe6c);
    *(undefined4 *)(param_1 + 0xe6c) = 0;
    return;
  }
  return;
}

