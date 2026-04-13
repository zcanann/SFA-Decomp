// Function: FUN_8026c794
// Entry: 8026c794
// Size: 244 bytes

int * FUN_8026c794(int param_1,byte param_2)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  piVar1 = DAT_803dee9c;
  if (DAT_803dee9c != (int *)0x0) {
    DAT_803dee9c = (int *)*DAT_803dee9c;
    if (DAT_803dee9c != (int *)0x0) {
      DAT_803dee9c[1] = 0;
    }
    piVar1[3] = param_1;
    *(byte *)(piVar1 + 4) = param_2;
    *(undefined *)((int)piVar1 + 0x11) =
         *(undefined *)(DAT_803dee98 + (uint)param_2 * 0x38 + 0x1518);
    puVar2 = *(undefined4 **)(DAT_803dee98 + (uint)*(byte *)((int)piVar1 + 0x11) * 4 + 0xe64);
    puVar4 = (undefined4 *)0x0;
    while (puVar3 = puVar2, puVar3 != (undefined4 *)0x0) {
      if (piVar1[3] < (int)puVar3[3]) {
        *piVar1 = (int)puVar3;
        piVar1[1] = (int)puVar4;
        if (puVar4 == (undefined4 *)0x0) {
          *(int **)(DAT_803dee98 + (uint)*(byte *)((int)piVar1 + 0x11) * 4 + 0xe64) = piVar1;
        }
        else {
          *puVar4 = piVar1;
        }
        puVar3[1] = piVar1;
        return piVar1;
      }
      puVar4 = puVar3;
      puVar2 = (undefined4 *)*puVar3;
    }
    piVar1[1] = (int)puVar4;
    if (puVar4 == (undefined4 *)0x0) {
      *(int **)(DAT_803dee98 + (uint)*(byte *)((int)piVar1 + 0x11) * 4 + 0xe64) = piVar1;
    }
    else {
      *puVar4 = piVar1;
    }
    *piVar1 = 0;
  }
  return piVar1;
}

