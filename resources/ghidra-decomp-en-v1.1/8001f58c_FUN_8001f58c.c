// Function: FUN_8001f58c
// Entry: 8001f58c
// Size: 132 bytes

int * FUN_8001f58c(int param_1,char param_2)

{
  int *piVar1;
  uint uVar2;
  
  if (param_2 == '\0') {
    piVar1 = FUN_8001df10(param_1);
    if (piVar1 == (int *)0x0) {
      piVar1 = (int *)0x0;
    }
  }
  else if (DAT_803dd6b0 < 0x32) {
    piVar1 = FUN_8001df10(param_1);
    if (piVar1 == (int *)0x0) {
      piVar1 = (int *)0x0;
    }
    else {
      uVar2 = (uint)DAT_803dd6b0;
      DAT_803dd6b0 = DAT_803dd6b0 + 1;
      (&DAT_8033cb20)[uVar2] = piVar1;
    }
  }
  else {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}

