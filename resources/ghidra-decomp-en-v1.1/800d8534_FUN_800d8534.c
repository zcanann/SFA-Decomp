// Function: FUN_800d8534
// Entry: 800d8534
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x800d8680) */
/* WARNING: Removing unreachable block (ram,0x800d8544) */

void FUN_800d8534(double param_1,ushort *param_2,uint *param_3)

{
  float local_88;
  float local_84;
  float fStack_80;
  ushort local_7c;
  ushort local_7a;
  undefined2 local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [19];
  
  if ((*param_3 & 0x2000000) == 0) {
    if ((*param_3 & 0x200000) == 0) {
      *(float *)(param_2 + 0x14) = *(float *)(param_2 + 0x14) * FLOAT_803e120c;
      *(float *)(param_2 + 0x14) =
           -(float)((double)(float)param_3[0xa9] * param_1 - (double)*(float *)(param_2 + 0x14));
    }
    if (((*(byte *)(param_3 + 0xd3) & 1) == 0) || ((*(byte *)(param_3 + 0xd3) & 4) != 0)) {
      local_7c = *param_2;
      local_7a = param_2[1];
      local_78 = 0;
      local_74 = FLOAT_803e1208;
      local_70 = FLOAT_803e11f0;
      local_6c = FLOAT_803e11f0;
      local_68 = FLOAT_803e11f0;
      FUN_80021fac(afStack_64,&local_7c);
      if ((*param_3 & 0x10000) == 0) {
        FUN_80022790((double)(float)param_3[0xa1],(double)FLOAT_803e11f0,
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,&fStack_80,&local_88);
      }
      else {
        FUN_80022790((double)(float)param_3[0xa1],(double)(float)param_3[0xa2],
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,(float *)(param_2 + 0x14),
                     &local_88);
      }
      *(float *)(param_2 + 0x12) = local_84;
      *(float *)(param_2 + 0x16) = local_88;
    }
    FUN_8002ba34((double)(float)((double)*(float *)(param_2 + 0x12) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x14) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x16) * param_1),(int)param_2);
  }
  return;
}

