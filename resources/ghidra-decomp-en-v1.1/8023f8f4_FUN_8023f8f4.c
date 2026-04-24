// Function: FUN_8023f8f4
// Entry: 8023f8f4
// Size: 416 bytes

void FUN_8023f8f4(uint param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_1c;
  int local_18;
  uint auStack_14 [3];
  
  iVar1 = (uint)*(byte *)((int)param_2 + 0x26) - (uint)DAT_803dc070;
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  *(char *)((int)param_2 + 0x26) = (char)iVar1;
  iVar1 = FUN_80036974(param_1,&uStack_1c,&local_18,auStack_14);
  if (((iVar1 != 0) && (*(char *)((int)param_2 + 0x26) == '\0')) && (local_18 == 0)) {
    *(char *)((int)param_2 + 0x25) = *(char *)((int)param_2 + 0x25) + -1;
    *(undefined *)((int)param_2 + 0x26) = 6;
    auStack_14[2] = DAT_803dd170 ^ 0x80000000;
    auStack_14[1] = 0x43300000;
    param_2[7] = (int)(float)((double)CONCAT44(0x43300000,auStack_14[2]) - DOUBLE_803e8238);
    FUN_8000bb38(param_1,0x484);
    if (*(char *)((int)param_2 + 0x25) == '\0') {
      *(undefined *)((int)param_2 + 0x23) = 9;
      FUN_8023ad80(*param_2,1);
      FUN_8000bb38(param_1,0x485);
      FUN_80038524(param_1,0,&local_20,&local_24,&local_28,0);
      FUN_8009abf8((double)local_20,(double)local_24,(double)local_28,(double)FLOAT_803e8240,in_f5,
                   in_f6,in_f7,in_f8,param_1,1,1,1,1,0,1,0);
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
  piVar2 = (int *)FUN_800395a4(param_1,0);
  *piVar2 = (uint)*(byte *)(param_2 + 10) << 8;
  return;
}

