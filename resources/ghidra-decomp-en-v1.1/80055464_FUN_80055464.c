// Function: FUN_80055464
// Entry: 80055464
// Size: 200 bytes

void FUN_80055464(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,char param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_803ddaf8;
  FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ddaf8,0x1c,
               param_9 << 4,0x10,param_13,param_14,param_15,param_16);
  DAT_80388600 = *puVar1;
  DAT_80388604 = puVar1[1];
  DAT_80388608 = puVar1[2];
  DAT_8038860c = *(undefined2 *)(puVar1 + 3);
  DAT_8038860e = *(undefined2 *)((int)puVar1 + 0xe);
  DAT_803ddb3a = (undefined2)param_9;
  DAT_803ddb3d = 1;
  DAT_803ddb3c = param_10;
  if (param_10 != '\0') {
    (**(code **)(*DAT_803dd6cc + 8))(2,1);
  }
  FUN_80130110(1);
  return;
}

