// Function: FUN_80115200
// Entry: 80115200
// Size: 280 bytes

/* WARNING: Removing unreachable block (ram,0x801152d0) */

void FUN_80115200(int param_1,undefined4 *param_2,undefined2 param_3,undefined2 param_4,int param_5)

{
  float fVar1;
  uint *puVar2;
  
  *(undefined2 *)(param_2 + 0x183) = param_3;
  *(undefined2 *)((int)param_2 + 0x60e) = param_4;
  *(char *)(param_2 + 0x184) = (char)param_5;
  param_2[0x17f] = 0;
  fVar1 = FLOAT_803e2910;
  *param_2 = FLOAT_803e2910;
  param_2[0x17e] = 0;
  param_2[0x181] = 0;
  param_2[0x182] = 0;
  param_2[0x185] = FLOAT_803e290c;
  *(undefined *)(param_2 + 0x180) = 0;
  *(undefined *)((int)param_2 + 0x601) = 1;
  param_2[1] = fVar1;
  param_2[2] = fVar1;
  param_2[3] = fVar1;
  param_2[0x186] = 0xffffffff;
  puVar2 = FUN_80039598();
  FUN_8003ad0c(param_1,puVar2,param_5);
  puVar2 = FUN_80039598();
  FUN_8003adf4(param_1,puVar2,param_5,(int)(param_2 + 7));
  FUN_8003aab8((int)(param_2 + 7),(uint)*(byte *)(param_2 + 0x184),0,0);
  FUN_80003494((uint)(param_2 + 0x16f),0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  FUN_80003494((int)param_2 + 0x5da,0x8031ad30,(uint)*(byte *)(param_2 + 0x184) << 1);
  return;
}

