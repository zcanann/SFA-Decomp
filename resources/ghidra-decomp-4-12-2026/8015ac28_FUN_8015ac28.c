// Function: FUN_8015ac28
// Entry: 8015ac28
// Size: 424 bytes

void FUN_8015ac28(uint param_1,int param_2)

{
  bool bVar1;
  
  bVar1 = false;
  switch(*(undefined2 *)(param_1 + 0xa0)) {
  case 2:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000b4f0(param_1,0x49b,2);
    }
    bVar1 = true;
    break;
  case 3:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000bb38(param_1,0x498);
    }
    break;
  case 4:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      if (FLOAT_803e3954 <= *(float *)(param_1 + 0x98)) {
        FUN_8000bb38(param_1,0x24e);
      }
      else {
        FUN_8000bb38(param_1,0x499);
      }
    }
    break;
  case 5:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000bb38(param_1,0x49d);
    }
    break;
  case 6:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000bb38(param_1,0x49d);
    }
    break;
  case 7:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000b4f0(param_1,0x49c,2);
    }
    bVar1 = true;
    break;
  case 9:
    if (*(short *)(param_2 + 0x2f8) != 0) {
      FUN_8000bb38(param_1,0x49a);
    }
  }
  if (bVar1) {
    if (*(short *)(param_2 + 0x338) == 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x809,0,2,0xffffffff,0);
    }
    else {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x802,0,2,0xffffffff,0);
    }
  }
  return;
}

