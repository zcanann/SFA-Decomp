// Function: FUN_80251ca4
// Entry: 80251ca4
// Size: 416 bytes

void FUN_80251ca4(int param_1,int *param_2)

{
  ushort uVar1;
  
  if (param_1 == 0) {
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
  }
  else {
    FUN_8025165c(*(undefined4 *)(param_1 + 0x18));
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(*(undefined4 *)(param_1 + 0x1c));
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(*(undefined4 *)(param_1 + 0x20));
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
  }
  FUN_8025165c(param_2[3]);
  do {
    uVar1 = FUN_80251624();
  } while (uVar1 != 0);
  FUN_8025165c(param_2[4]);
  do {
    uVar1 = FUN_80251624();
  } while (uVar1 != 0);
  FUN_8025165c(param_2[5]);
  do {
    uVar1 = FUN_80251624();
  } while (uVar1 != 0);
  if (*param_2 == 0) {
    FUN_8025165c((uint)*(ushort *)(param_2 + 9));
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(0);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
  }
  else {
    FUN_8025165c((uint)*(ushort *)((int)param_2 + 0x26));
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(param_2[6]);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(param_2[7]);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
    FUN_8025165c(param_2[8]);
    do {
      uVar1 = FUN_80251624();
    } while (uVar1 != 0);
  }
  return;
}

