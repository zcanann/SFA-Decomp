// Function: FUN_80222410
// Entry: 80222410
// Size: 212 bytes

void FUN_80222410(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float *param_10,float *param_11)

{
  int iVar1;
  undefined8 uVar2;
  short asStack_48 [4];
  short asStack_40 [4];
  short asStack_38 [4];
  float afStack_30 [3];
  float local_24;
  float local_20;
  float local_1c;
  
  FUN_80247ef8(param_11,param_11);
  FUN_80247edc(param_1,param_11,afStack_30);
  FUN_80247e94(afStack_30,param_10,&local_24);
  FUN_80012d20(param_10,asStack_38);
  uVar2 = FUN_80012d20(&local_24,asStack_40);
  iVar1 = FUN_800128fc(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_38,
                       asStack_40,(undefined4 *)asStack_48,(undefined *)0x0,0);
  if (iVar1 == 0) {
    FUN_80012e2c(&local_24,asStack_48);
  }
  *param_9 = local_24;
  param_9[1] = local_20;
  param_9[2] = local_1c;
  return;
}

