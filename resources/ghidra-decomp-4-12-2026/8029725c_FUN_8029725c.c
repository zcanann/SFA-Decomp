// Function: FUN_8029725c
// Entry: 8029725c
// Size: 116 bytes

void FUN_8029725c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  char *pcVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  pcVar1 = *(char **)(iVar2 + 0x35c);
  iVar3 = *pcVar1 + param_10;
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (pcVar1[1] < iVar3) {
    iVar3 = (int)pcVar1[1];
  }
  *pcVar1 = (char)iVar3;
  if (**(char **)(iVar2 + 0x35c) < '\x01') {
    FUN_802ab1e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

