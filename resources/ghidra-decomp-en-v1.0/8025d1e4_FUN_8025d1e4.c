// Function: FUN_8025d1e4
// Entry: 8025d1e4
// Size: 284 bytes

void FUN_8025d1e4(double param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,int param_7)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = FLOAT_803e7754;
  if (param_7 == 0) {
    param_2 = (double)(float)(param_2 - (double)FLOAT_803e7750);
  }
  dVar3 = (double)FLOAT_803e7750;
  dVar2 = (double)FLOAT_803e7758;
  dVar7 = (double)(float)(param_3 * dVar3);
  *(float *)(DAT_803dc5a8 + 0x43c) = (float)param_1;
  dVar6 = (double)(float)(dVar2 * param_6);
  *(float *)(DAT_803dc5a8 + 0x440) = (float)param_2;
  dVar5 = (double)(float)(-param_4 * dVar3);
  dVar4 = (double)(fVar1 + (float)(param_1 + dVar7));
  *(float *)(DAT_803dc5a8 + 0x444) = (float)param_3;
  dVar3 = (double)(fVar1 + (float)(param_2 + (double)(float)(param_4 * dVar3)));
  dVar2 = (double)(float)(dVar6 - (double)(float)(dVar2 * param_5));
  *(float *)(DAT_803dc5a8 + 0x448) = (float)param_4;
  *(float *)(DAT_803dc5a8 + 0x44c) = (float)param_5;
  *(float *)(DAT_803dc5a8 + 0x450) = (float)param_6;
  if (*(char *)(DAT_803dc5a8 + 0x454) != '\0') {
    FUN_8025cd38(param_5,(double)*(float *)(DAT_803dc5a8 + 0x458));
  }
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x5101a);
  write_volatile_4(0xcc008000,(float)dVar7);
  write_volatile_4(0xcc008000,(float)dVar5);
  write_volatile_4(0xcc008000,(float)dVar2);
  write_volatile_4(0xcc008000,(float)dVar4);
  write_volatile_4(0xcc008000,(float)dVar3);
  write_volatile_4(0xcc008000,(float)dVar6);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

