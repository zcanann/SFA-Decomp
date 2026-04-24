// Function: FUN_8001628c
// Entry: 8001628c
// Size: 312 bytes

void FUN_8001628c(uint param_1,undefined4 param_2,undefined4 param_3,int *param_4,int *param_5,
                 int *param_6,int *param_7)

{
  bool bVar1;
  int iVar2;
  ushort *puVar3;
  
  if (*(int *)(DAT_803dc9ec + 0x1c) == 2) {
    puVar3 = *(ushort **)(DAT_803dc9ec + 4);
    for (iVar2 = *(int *)(DAT_803dc9ec + 0xc); iVar2 != 0; iVar2 = iVar2 + -1) {
      if (*puVar3 == param_1) {
        bVar1 = true;
        goto LAB_80016304;
      }
      puVar3 = puVar3 + 6;
    }
    bVar1 = false;
  }
  else {
    bVar1 = false;
  }
LAB_80016304:
  if (bVar1) {
    DAT_803dc9bc = 1;
    DAT_803dc9b0 = 0x7fffffff;
    DAT_803dc9ac = 0;
    DAT_803dc9b8 = 0x7fffffff;
    DAT_803dc9b4 = 0;
    FUN_8001658c();
    DAT_803dc9bc = 0;
    if (param_6 != (int *)0x0) {
      *param_6 = DAT_803dc9b8 >> 2;
    }
    if (param_7 != (int *)0x0) {
      *param_7 = DAT_803dc9b4 >> 2;
    }
    if (param_4 != (int *)0x0) {
      *param_4 = DAT_803dc9b0 >> 2;
    }
    if (param_5 != (int *)0x0) {
      *param_5 = DAT_803dc9ac >> 2;
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

