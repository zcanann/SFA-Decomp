// Function: FUN_8000e840
// Entry: 8000e840
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x8000e940) */

void FUN_8000e840(double param_1,undefined4 param_2,undefined4 param_3,ushort *param_4,
                 float *param_5)

{
  float *pfVar1;
  uint unaff_GQR0;
  
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  pfVar1 = param_5;
  if (param_5 == (float *)0x0) {
    pfVar1 = (float *)&DAT_80338df0;
  }
  *(float *)(param_4 + 6) = *(float *)(param_4 + 6) - FLOAT_803dda58;
  *(float *)(param_4 + 10) = *(float *)(param_4 + 10) - FLOAT_803dda5c;
  FUN_80021fac(pfVar1,param_4);
  if ((double)FLOAT_803df270 != param_1) {
    FUN_80021f84(param_1,(int)pfVar1);
  }
  if (param_5 == (float *)0x0) {
    FUN_800216cc(pfVar1,(undefined4 *)&DAT_80397420);
  }
  else {
    FUN_800216cc(param_5,(undefined4 *)&DAT_80397420);
  }
  FUN_80247618((float *)&DAT_80339330,(float *)&DAT_80397420,(float *)&DAT_80397420);
  FUN_8025d80c((float *)&DAT_80397420,0);
  *(float *)(param_4 + 6) = *(float *)(param_4 + 6) + FLOAT_803dda58;
  *(float *)(param_4 + 10) = *(float *)(param_4 + 10) + FLOAT_803dda5c;
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  return;
}

