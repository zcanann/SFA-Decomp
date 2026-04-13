// Function: FUN_801db480
// Entry: 801db480
// Size: 276 bytes

void FUN_801db480(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int *piVar4;
  
  piVar4 = *(int **)(param_9 + 0x5c);
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  param_9[0x58] = param_9[0x58] | 0x4000;
  uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x1e));
  *(char *)(piVar4 + 5) = (char)uVar1;
  if ((*(char *)(piVar4 + 5) == '\0') &&
     (uVar1 = FUN_80020078((int)*(short *)(param_10 + 0x20)), uVar1 != 0)) {
    *(undefined *)(piVar4 + 5) = 2;
  }
  if ((*(char *)(piVar4 + 5) != '\0') && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_8002becc(0x20,0x55);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 10);
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(*(int *)(param_9 + 0x26) + 5);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(*(int *)(param_9 + 0x26) + 7);
    iVar3 = FUN_8002b678(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)param_9,puVar2);
    *piVar4 = iVar3;
  }
  *(code **)(param_9 + 0x5e) = FUN_801daf44;
  return;
}

