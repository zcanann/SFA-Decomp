// Function: FUN_801d049c
// Entry: 801d049c
// Size: 84 bytes

void FUN_801d049c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  char cVar1;
  undefined8 extraout_f1;
  
  cVar1 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(param_9 + 0xac),0);
  if (cVar1 == '\0') {
    FUN_80088a84(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  }
  FUN_800146a8();
  return;
}

