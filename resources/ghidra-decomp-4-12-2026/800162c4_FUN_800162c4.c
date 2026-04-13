// Function: FUN_800162c4
// Entry: 800162c4
// Size: 312 bytes

void FUN_800162c4(uint param_1,undefined4 param_2,undefined4 param_3,int *param_4,int *param_5,
                 int *param_6,int *param_7)

{
  bool bVar1;
  int iVar2;
  ushort *puVar3;
  undefined8 in_f1;
  undefined8 in_f2;
  undefined8 in_f3;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  if (*(int *)(DAT_803dd66c + 0x1c) == 2) {
    puVar3 = *(ushort **)(DAT_803dd66c + 4);
    for (iVar2 = *(int *)(DAT_803dd66c + 0xc); iVar2 != 0; iVar2 = iVar2 + -1) {
      if (*puVar3 == param_1) {
        bVar1 = true;
        goto LAB_8001633c;
      }
      puVar3 = puVar3 + 6;
    }
    bVar1 = false;
  }
  else {
    bVar1 = false;
  }
LAB_8001633c:
  if (bVar1) {
    DAT_803dd63c = 1;
    DAT_803dd630 = 0x7fffffff;
    DAT_803dd62c = 0;
    DAT_803dd638 = 0x7fffffff;
    DAT_803dd634 = 0;
    FUN_800165c4(in_f1,in_f2,in_f3,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,param_2,param_3);
    DAT_803dd63c = 0;
    if (param_6 != (int *)0x0) {
      *param_6 = DAT_803dd638 >> 2;
    }
    if (param_7 != (int *)0x0) {
      *param_7 = DAT_803dd634 >> 2;
    }
    if (param_4 != (int *)0x0) {
      *param_4 = DAT_803dd630 >> 2;
    }
    if (param_5 != (int *)0x0) {
      *param_5 = DAT_803dd62c >> 2;
    }
  }
  else {
    *param_4 = 0;
    *param_5 = 0;
    *param_6 = 0;
    *param_7 = 0;
  }
  return;
}

