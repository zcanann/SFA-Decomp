// Function: FUN_80251540
// Entry: 80251540
// Size: 416 bytes

void FUN_80251540(int param_1,int *param_2)

{
  int iVar1;
  
  if (param_1 == 0) {
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
  }
  else {
    FUN_80250ef8(*(undefined4 *)(param_1 + 0x18));
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(*(undefined4 *)(param_1 + 0x1c));
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(*(undefined4 *)(param_1 + 0x20));
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
  }
  FUN_80250ef8(param_2[3]);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(param_2[4]);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  FUN_80250ef8(param_2[5]);
  do {
    iVar1 = FUN_80250ec0();
  } while (iVar1 != 0);
  if (*param_2 == 0) {
    FUN_80250ef8(*(undefined2 *)(param_2 + 9));
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(0);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
  }
  else {
    FUN_80250ef8(*(undefined2 *)((int)param_2 + 0x26));
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(param_2[6]);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(param_2[7]);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
    FUN_80250ef8(param_2[8]);
    do {
      iVar1 = FUN_80250ec0();
    } while (iVar1 != 0);
  }
  return;
}

