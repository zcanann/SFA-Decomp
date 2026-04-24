// Function: FUN_8023fa94
// Entry: 8023fa94
// Size: 144 bytes

void FUN_8023fa94(int param_1,char param_2,char param_3)

{
  int *piVar1;
  
  if (param_1 != 0) {
    piVar1 = *(int **)(param_1 + 0xb8);
    if ((*(char *)((int)piVar1 + 0x23) == '\t') && (param_3 == '\0')) {
      if (param_2 != '\0') {
        FUN_8023ad80(*piVar1,1);
      }
    }
    else {
      *(char *)((int)piVar1 + 0x23) = param_2;
      if (param_3 != '\0') {
        if (param_3 == '\x02') {
          *(undefined *)((int)piVar1 + 0x25) = 0x12;
        }
        else {
          *(undefined *)((int)piVar1 + 0x25) = 0xf;
        }
      }
    }
  }
  return;
}

