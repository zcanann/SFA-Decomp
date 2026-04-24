// Function: FUN_80207bec
// Entry: 80207bec
// Size: 96 bytes

void FUN_80207bec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_9 + 0xb8) + 0xe);
  if (cVar1 == '\0') {
    FUN_802077c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if (cVar1 == '\x01') {
    FUN_80207568(param_9);
  }
  else if (cVar1 == '\x02') {
    FUN_80207250();
  }
  else if (cVar1 == '\x03') {
    FUN_80206fa0();
  }
  return;
}

