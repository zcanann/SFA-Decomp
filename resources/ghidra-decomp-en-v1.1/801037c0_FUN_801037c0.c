// Function: FUN_801037c0
// Entry: 801037c0
// Size: 316 bytes

undefined4
FUN_801037c0(double param_1,float *param_2,float *param_3,float *param_4,int param_5,
            undefined param_6,char param_7,char param_8)

{
  char cVar2;
  undefined4 uVar1;
  float local_40 [3];
  uint auStack_34 [9];
  
  if (param_4 == (float *)0x0) {
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
    cVar2 = FUN_80064248(param_2,param_4,(float *)0x1,(int *)0x0,(int *)0x0,0x10,0xffffffff,0xff,0);
  }
  DAT_803de1a0 = cVar2;
  if (param_7 != '\0') {
    FUN_80069798(auStack_34,param_2,param_4,(float *)(param_5 + 0x40),1);
    FUN_8006933c(0,auStack_34,0x240,'\x01');
  }
  FUN_80067ad4();
  uVar1 = 0;
  if ((DAT_803de1a0 == '\0') && (*(short *)(param_5 + 0x6c) == 0)) {
    uVar1 = 1;
  }
  return uVar1;
}

