// Function: FUN_8022387c
// Entry: 8022387c
// Size: 288 bytes

void FUN_8022387c(undefined2 *param_1,int param_2)

{
  int iVar1;
  char cVar2;
  int iVar3;
  undefined4 local_18 [3];
  
  iVar3 = *(int *)(param_1 + 0x5c);
  local_18[0] = DAT_803e6cd8;
  *(code **)(param_1 + 0x5e) = FUN_80223004;
  FUN_80114f64(param_1,iVar3,0xffffe000,0x31c7,2);
  FUN_80113f9c(iVar3,0,local_18,2);
  FUN_80113f94((double)FLOAT_803e6ce8,iVar3);
  *(byte *)(iVar3 + 0x611) = *(byte *)(iVar3 + 0x611) | 2;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)(iVar3 + 0x65b) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(iVar3 + 0x65b) == '\x01') {
    iVar1 = FUN_8001ffb4(0x7fc);
    if ((iVar1 == 0) &&
       (cVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0x56)), cVar2 != '\x02'
       )) {
      *(undefined *)(iVar3 + 0x658) = 0;
    }
    else {
      *(undefined *)(iVar3 + 0x658) = 2;
    }
  }
  else {
    *(undefined *)(iVar3 + 0x658) = 2;
  }
  *(undefined *)(iVar3 + 0x65c) = 0xff;
  return;
}

