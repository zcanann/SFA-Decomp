// Function: FUN_80187a7c
// Entry: 80187a7c
// Size: 284 bytes

void FUN_80187a7c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  
  piVar5 = *(int **)(param_9 + 0xb8);
  *(code **)(param_9 + 0xbc) = FUN_801877e4;
  iVar2 = FUN_8002bac4();
  if (*(short *)(iVar2 + 0x46) == 0) {
    *(undefined2 *)(piVar5 + 8) = 0x5d6;
  }
  else {
    *(undefined2 *)(piVar5 + 8) = 0x13d;
  }
  *(undefined *)(piVar5 + 7) = 0;
  uVar3 = FUN_80020078((int)*(short *)(piVar5 + 8));
  *(char *)((int)piVar5 + 0x1d) = (char)uVar3;
  if (*(char *)(param_10 + 0x19) == '\x01') {
    if (*(char *)((int)piVar5 + 0x1d) != '\0') {
      *(undefined *)(piVar5 + 7) = 1;
      iVar2 = FUN_80187720(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      *piVar5 = iVar2;
    }
    *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
  }
  else {
    bVar1 = *(byte *)((int)piVar5 + 0x1d);
    if (5 < bVar1) {
      bVar1 = 6;
    }
    *(byte *)(piVar5 + 7) = bVar1;
    piVar6 = piVar5;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(piVar5 + 7); iVar2 = iVar2 + 1) {
      iVar4 = FUN_80187720(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      *piVar6 = iVar4;
      piVar6 = piVar6 + 1;
    }
  }
  return;
}

