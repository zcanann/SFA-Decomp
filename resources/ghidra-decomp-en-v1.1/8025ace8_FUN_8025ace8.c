// Function: FUN_8025ace8
// Entry: 8025ace8
// Size: 404 bytes

void FUN_8025ace8(double param_1,double param_2,double param_3,uint *param_4,int param_5,int param_6
                 ,uint param_7,char param_8,int param_9)

{
  double dVar1;
  double dVar2;
  
  dVar1 = (double)FLOAT_803e8378;
  if ((dVar1 <= param_3) && (dVar1 = param_3, (double)FLOAT_803e837c <= param_3)) {
    dVar1 = (double)FLOAT_803e8380;
  }
  *param_4 = ((int)((double)FLOAT_803e8384 * dVar1) & 0xffU) << 9 | *param_4 & 0xfffe01ff;
  *param_4 = *param_4 & 0xffffffef | (uint)(param_6 == 1) << 4;
  *param_4 = *param_4 & 0xffffff1f | (uint)(byte)(&DAT_803dd260)[param_5] << 5;
  *param_4 = *param_4 & 0xfffffeff | (uint)(param_8 == '\0') << 8;
  *param_4 = *param_4 & 0xfffdffff;
  *param_4 = *param_4 & 0xfffbffff;
  *param_4 = *param_4 & 0xffe7ffff | param_9 << 0x13;
  *param_4 = *param_4 & 0xffdfffff | (param_7 & 0xff) << 0x15;
  dVar1 = (double)FLOAT_803e8388;
  if ((dVar1 <= param_1) && (dVar1 = param_1, (double)FLOAT_803e838c < param_1)) {
    dVar1 = (double)FLOAT_803e838c;
  }
  dVar2 = (double)FLOAT_803e8388;
  if ((dVar2 <= param_2) && (dVar2 = param_2, (double)FLOAT_803e838c < param_2)) {
    dVar2 = (double)FLOAT_803e838c;
  }
  param_4[1] = (int)((double)FLOAT_803e8368 * dVar1) & 0xffU | param_4[1] & 0xffffff00;
  param_4[1] = ((int)((double)FLOAT_803e8368 * dVar2) & 0xffU) << 8 | param_4[1] & 0xffff00ff;
  return;
}

