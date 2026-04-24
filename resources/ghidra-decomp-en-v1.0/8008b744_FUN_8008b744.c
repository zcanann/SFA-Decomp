// Function: FUN_8008b744
// Entry: 8008b744
// Size: 164 bytes

void FUN_8008b744(double param_1,short *param_2,short *param_3,short *param_4)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (int)param_1;
  *param_2 = ((short)(iVar2 / 0x34bc0) + (short)(iVar2 >> 0x1f)) -
             (short)(iVar2 / 0x34bc0 + (iVar2 >> 0x1f) >> 0x1f);
  iVar2 = iVar2 + *param_2 * -0x34bc0;
  iVar1 = iVar2 / 0xe10 + (iVar2 >> 0x1f);
  *param_3 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar2 = iVar2 + *param_3 * -0xe10;
  iVar2 = iVar2 / 0x3c + (iVar2 >> 0x1f);
  *param_4 = (short)iVar2 - (short)(iVar2 >> 0x1f);
  return;
}

