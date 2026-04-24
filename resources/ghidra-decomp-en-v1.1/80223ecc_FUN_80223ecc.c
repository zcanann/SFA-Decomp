// Function: FUN_80223ecc
// Entry: 80223ecc
// Size: 288 bytes

void FUN_80223ecc(undefined2 *param_1,int param_2)

{
  uint uVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 local_18 [3];
  
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  local_18[0] = DAT_803e7970;
  *(code **)(param_1 + 0x5e) = FUN_80223654;
  FUN_80115200((int)param_1,puVar3,0xe000,0x31c7,2);
  FUN_80114238((int)puVar3,(wchar_t *)0x0,(wchar_t *)local_18);
  FUN_80114230((double)FLOAT_803e7980,(int)puVar3);
  *(byte *)((int)puVar3 + 0x611) = *(byte *)((int)puVar3 + 0x611) | 2;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined *)((int)puVar3 + 0x65b) = *(undefined *)(param_2 + 0x19);
  if (*(char *)((int)puVar3 + 0x65b) == '\x01') {
    uVar1 = FUN_80020078(0x7fc);
    if ((uVar1 == 0) &&
       (cVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56)), cVar2 != '\x02'
       )) {
      *(undefined *)(puVar3 + 0x196) = 0;
    }
    else {
      *(undefined *)(puVar3 + 0x196) = 2;
    }
  }
  else {
    *(undefined *)(puVar3 + 0x196) = 2;
  }
  *(undefined *)(puVar3 + 0x197) = 0xff;
  return;
}

