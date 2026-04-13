// Function: FUN_800d921c
// Entry: 800d921c
// Size: 460 bytes

/* WARNING: Removing unreachable block (ram,0x800d93c4) */
/* WARNING: Removing unreachable block (ram,0x800d922c) */

void FUN_800d921c(double param_1,short *param_2,uint *param_3,uint param_4)

{
  float fVar1;
  undefined uVar2;
  float *pfVar3;
  int iVar4;
  float local_48;
  float local_44;
  float local_40;
  short local_3a;
  char local_36;
  char local_35 [8];
  char local_2d;
  
  local_36 = '\0';
  uVar2 = FUN_8002fb40((double)(float)param_3[0xa8],param_1);
  *(undefined *)((int)param_3 + 0x346) = uVar2;
  param_3[0xc5] = 0;
  pfVar3 = &local_48;
  for (iVar4 = 0; iVar4 < local_2d; iVar4 = iVar4 + 1) {
    param_3[0xc5] = param_3[0xc5] | 1 << (int)*(char *)((int)pfVar3 + 0x13);
    pfVar3 = (float *)((int)pfVar3 + 1);
  }
  *param_3 = *param_3 & 0xfffeffff;
  fVar1 = FLOAT_803e11f0;
  if (local_36 == '\0') {
    param_3[0xa0] = (uint)FLOAT_803e11f0;
    param_3[0xa1] = (uint)fVar1;
  }
  else if ((param_4 & 0x10) == 0) {
    if ((param_4 & 1) != 0) {
      param_3[0xa0] = (uint)(float)(-(double)local_40 / param_1);
    }
    if ((param_4 & 2) != 0) {
      param_3[0xa1] = (uint)(float)((double)local_48 / param_1);
    }
    if ((param_4 & 8) != 0) {
      *param_2 = *param_2 + local_3a;
    }
    if ((param_4 & 4) != 0) {
      param_3[0xa2] = (uint)(float)((double)local_44 / param_1);
      *param_3 = *param_3 | 0x10000;
    }
  }
  else {
    if ((param_4 & 1) != 0) {
      param_3[0xad] = (uint)-local_40;
    }
    if ((param_4 & 2) != 0) {
      param_3[0xad] = (uint)local_48;
    }
    if ((param_4 & 4) != 0) {
      param_3[0xad] = (uint)local_44;
    }
    if ((param_4 & 8) != 0) {
      *param_2 = *param_2 + local_3a;
    }
  }
  DAT_803de0c0 = 1;
  return;
}

