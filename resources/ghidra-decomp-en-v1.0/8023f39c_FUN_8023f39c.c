// Function: FUN_8023f39c
// Entry: 8023f39c
// Size: 144 bytes

void FUN_8023f39c(int param_1,char param_2,char param_3)

{
  undefined4 *puVar1;
  
  if (param_1 != 0) {
    puVar1 = *(undefined4 **)(param_1 + 0xb8);
    if ((*(char *)((int)puVar1 + 0x23) == '\t') && (param_3 == '\0')) {
      if (param_2 != '\0') {
        FUN_8023a688(*puVar1,1);
      }
    }
    else {
      *(char *)((int)puVar1 + 0x23) = param_2;
      if (param_3 != '\0') {
        if (param_3 == '\x02') {
          *(undefined *)((int)puVar1 + 0x25) = 0x12;
        }
        else {
          *(undefined *)((int)puVar1 + 0x25) = 0xf;
        }
      }
    }
  }
  return;
}

