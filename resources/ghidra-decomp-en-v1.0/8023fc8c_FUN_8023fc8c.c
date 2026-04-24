// Function: FUN_8023fc8c
// Entry: 8023fc8c
// Size: 112 bytes

void FUN_8023fc8c(int param_1,undefined param_2,char param_3)

{
  undefined4 *puVar1;
  
  if (param_1 != 0) {
    puVar1 = *(undefined4 **)(param_1 + 0xb8);
    if ((*(char *)(puVar1 + 7) == '\x02') && (param_3 == '\0')) {
      FUN_8023a688(*puVar1,1);
    }
    else {
      *(undefined *)(puVar1 + 7) = param_2;
      if (param_3 != '\0') {
        *(undefined *)((int)puVar1 + 0x1e) = 0x50;
      }
    }
  }
  return;
}

