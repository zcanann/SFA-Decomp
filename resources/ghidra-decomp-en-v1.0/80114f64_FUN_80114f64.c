// Function: FUN_80114f64
// Entry: 80114f64
// Size: 280 bytes

/* WARNING: Removing unreachable block (ram,0x80115034) */

void FUN_80114f64(undefined4 param_1,float *param_2,undefined2 param_3,undefined2 param_4,
                 undefined4 param_5)

{
  float fVar1;
  undefined4 uVar2;
  
  *(undefined2 *)(param_2 + 0x183) = param_3;
  *(undefined2 *)((int)param_2 + 0x60e) = param_4;
  *(char *)(param_2 + 0x184) = (char)param_5;
  param_2[0x17f] = 0.0;
  fVar1 = FLOAT_803e1c90;
  *param_2 = FLOAT_803e1c90;
  param_2[0x17e] = 0.0;
  param_2[0x181] = 0.0;
  param_2[0x182] = 0.0;
  param_2[0x185] = FLOAT_803e1c8c;
  *(undefined *)(param_2 + 0x180) = 0;
  *(undefined *)((int)param_2 + 0x601) = 1;
  param_2[1] = fVar1;
  param_2[2] = fVar1;
  param_2[3] = fVar1;
  param_2[0x186] = -NAN;
  uVar2 = FUN_800394a0();
  FUN_8003ac14(param_1,uVar2,param_5);
  uVar2 = FUN_800394a0();
  FUN_8003acfc(param_1,uVar2,param_5,param_2 + 7);
  FUN_8003a9c0(param_2 + 7,*(undefined *)(param_2 + 0x184),0,0);
  FUN_80003494(param_2 + 0x16f,u____________8031a0e0,(uint)*(byte *)(param_2 + 0x184) << 1);
  FUN_80003494((int)param_2 + 0x5da,u____________8031a0e0,(uint)*(byte *)(param_2 + 0x184) << 1);
  return;
}

