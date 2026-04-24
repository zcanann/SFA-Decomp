// Function: FUN_80103524
// Entry: 80103524
// Size: 316 bytes

undefined4
FUN_80103524(double param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,int param_5,
            undefined param_6,char param_7,char param_8)

{
  char cVar2;
  undefined4 uVar1;
  undefined4 local_40 [3];
  undefined auStack52 [36];
  
  if (param_4 == (undefined4 *)0x0) {
    param_4 = local_40;
  }
  *param_4 = *param_3;
  param_4[1] = param_3[1];
  param_4[2] = param_3[2];
  *(float *)(param_5 + 0x40) = (float)param_1;
  *(undefined *)(param_5 + 0x50) = 0xff;
  *(undefined *)(param_5 + 0x54) = param_6;
  *(undefined2 *)(param_5 + 0x6c) = 0;
  cVar2 = '\0';
  if (param_8 != '\0') {
    cVar2 = FUN_800640cc(param_2,param_4,1,0,0,0x10,0xffffffff,0xff,0);
  }
  DAT_803dd528 = cVar2;
  if (param_7 != '\0') {
    FUN_8006961c(auStack52,param_2,param_4,param_5 + 0x40,1);
    FUN_800691c0(0,auStack52,0x240,1);
  }
  FUN_80067958(0,param_2,param_4,1,param_5,0);
  uVar1 = 0;
  if ((DAT_803dd528 == '\0') && (*(short *)(param_5 + 0x6c) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}

