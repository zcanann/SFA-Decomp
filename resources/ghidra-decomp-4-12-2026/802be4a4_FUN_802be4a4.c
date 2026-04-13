// Function: FUN_802be4a4
// Entry: 802be4a4
// Size: 208 bytes

/* WARNING: Removing unreachable block (ram,0x802be554) */
/* WARNING: Removing unreachable block (ram,0x802be4b4) */

void FUN_802be4a4(double param_1,int param_2)

{
  float *pfVar1;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  ushort local_3c [4];
  float local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  pfVar1 = (float *)FUN_80038498(param_2,2);
  FUN_800383e8(param_2,2,&local_40,&local_44,&local_48);
  local_30 = local_40;
  local_2c = local_44;
  local_28 = local_48;
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_34 = (float)(param_1 / (double)*(float *)(*(int *)(param_2 + 0x50) + 4));
  FUN_80021fac((float *)&DAT_803dbdd0,local_3c);
  FUN_800223a8((float *)&DAT_803dbdd0,pfVar1,(float *)&DAT_803dbdd0);
  FUN_8003ba48(&DAT_803dbdd0);
  return;
}

