// Function: FUN_8023f1fc
// Entry: 8023f1fc
// Size: 416 bytes

void FUN_8023f1fc(undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  int *piVar2;
  float local_28;
  float local_24;
  float local_20;
  undefined auStack28 [4];
  int local_18;
  undefined auStack20 [4];
  undefined4 local_10;
  uint uStack12;
  
  iVar1 = (uint)*(byte *)((int)param_2 + 0x26) - (uint)DAT_803db410;
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  *(char *)((int)param_2 + 0x26) = (char)iVar1;
  iVar1 = FUN_8003687c(param_1,auStack28,&local_18,auStack20);
  if (((iVar1 != 0) && (*(char *)((int)param_2 + 0x26) == '\0')) && (local_18 == 0)) {
    *(char *)((int)param_2 + 0x25) = *(char *)((int)param_2 + 0x25) + -1;
    *(undefined *)((int)param_2 + 0x26) = 6;
    uStack12 = DAT_803dc508 ^ 0x80000000;
    local_10 = 0x43300000;
    param_2[7] = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e75a0);
    FUN_8000bb18(param_1,0x484);
    if (*(char *)((int)param_2 + 0x25) == '\0') {
      *(undefined *)((int)param_2 + 0x23) = 9;
      FUN_8023a688(*param_2,1);
      FUN_8000bb18(param_1,0x485);
      FUN_8003842c(param_1,0,&local_20,&local_24,&local_28,0);
      FUN_8009a96c((double)local_20,(double)local_24,(double)local_28,(double)FLOAT_803e75a8,param_1
                   ,1,1,1,1,0,1,0);
    }
  }
  if (*(char *)((int)param_2 + 0x25) == '\0') {
    *(undefined *)(param_2 + 10) = 2;
  }
  else if (*(char *)((int)param_2 + 0x26) == '\0') {
    *(undefined *)(param_2 + 10) = 0;
  }
  else {
    *(undefined *)(param_2 + 10) = 1;
  }
  piVar2 = (int *)FUN_800394ac(param_1,0,0);
  *piVar2 = (uint)*(byte *)(param_2 + 10) << 8;
  return;
}

