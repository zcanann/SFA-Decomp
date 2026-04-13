// Function: FUN_801cd480
// Entry: 801cd480
// Size: 208 bytes

void FUN_801cd480(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  undefined uVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if (*(char *)(iVar3 + 0x19) == '\0') {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  uVar4 = FUN_80035eec(param_9,0xe,uVar2,0);
  cVar1 = *(char *)(iVar3 + 0x19);
  if (cVar1 == '\x01') {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x203
                 ,0,0,0,in_r9,in_r10);
  }
  else if (cVar1 == '\x02') {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x204
                 ,0,0,0,in_r9,in_r10);
  }
  else {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x201
                 ,0,0,0,in_r9,in_r10);
  }
  return;
}

