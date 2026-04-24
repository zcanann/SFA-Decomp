// Function: FUN_80240384
// Entry: 80240384
// Size: 112 bytes

void FUN_80240384(int param_1,undefined param_2,char param_3)

{
  int *piVar1;
  
  if (param_1 != 0) {
    piVar1 = *(int **)(param_1 + 0xb8);
    if ((*(char *)(piVar1 + 7) == '\x02') && (param_3 == '\0')) {
      FUN_8023ad80(*piVar1,1);
    }
    else {
      *(undefined *)(piVar1 + 7) = param_2;
      if (param_3 != '\0') {
        *(undefined *)((int)piVar1 + 0x1e) = 0x50;
      }
    }
  }
  return;
}

