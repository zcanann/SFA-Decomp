// Function: FUN_800a2294
// Entry: 800a2294
// Size: 208 bytes

void FUN_800a2294(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int *piVar1;
  int iVar2;
  uint *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_8039ce58;
  do {
    piVar1 = (int *)*puVar3;
    if ((piVar1 != (int *)0x0) && (piVar1[1] == param_9)) {
      if (*piVar1 != 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
      }
      *(undefined4 *)(*puVar3 + 300) = 0;
      if ((*(char *)(*puVar3 + 0x13f) == '\0') && (*(int *)(*puVar3 + 0x98) != 0)) {
        FUN_80054484();
      }
      if (*(char *)(*puVar3 + 0x13f) == '\0') {
        *(undefined4 *)(*puVar3 + 0x98) = 0;
      }
      param_1 = FUN_800238c4(*puVar3);
      *puVar3 = 0;
    }
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x32);
  return;
}

