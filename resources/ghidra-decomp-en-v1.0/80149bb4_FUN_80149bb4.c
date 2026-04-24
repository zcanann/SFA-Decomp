// Function: FUN_80149bb4
// Entry: 80149bb4
// Size: 312 bytes

void FUN_80149bb4(double param_1,int param_2,uint param_3,undefined2 param_4)

{
  *(undefined *)(param_2 + 0x2f1) = 0;
  if ((param_3 & 2) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x20;
  }
  if ((param_3 & 1) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x40;
  }
  if ((param_3 & 4) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 1;
  }
  if ((param_3 & 8) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 2;
  }
  if ((param_3 & 0x10) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 4;
  }
  if ((double)FLOAT_803e25a4 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 8;
  }
  else if ((double)FLOAT_803e2594 == param_1) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x10;
  }
  if ((param_3 & 0x80) != 0) {
    *(byte *)(param_2 + 0x2f1) = *(byte *)(param_2 + 0x2f1) | 0x80;
  }
  if ((param_3 & 0x100) == 0) {
    if ((param_3 & 0x200) == 0) {
      if ((param_3 & 0x400) != 0) {
        *(undefined *)(param_2 + 0x2f5) = 3;
      }
    }
    else {
      *(undefined *)(param_2 + 0x2f5) = 2;
    }
  }
  else {
    *(undefined *)(param_2 + 0x2f5) = 1;
  }
  *(undefined2 *)(param_2 + 0x2ec) = param_4;
  return;
}

