// Function: FUN_801534ec
// Entry: 801534ec
// Size: 520 bytes

void FUN_801534ec(ushort *param_1,undefined4 *param_2)

{
  int iVar1;
  char cVar2;
  float *pfVar3;
  float local_28;
  float local_24;
  float local_20;
  
  pfVar3 = (float *)*param_2;
  if (*(int *)(param_1 + 0x2a) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  }
  if (*(char *)((int)param_2 + 0x33b) != '\0') {
    param_2[0xba] = param_2[0xba] | 0x80;
  }
  if ((param_2[0xb7] & 0x2000) != 0) {
    iVar1 = FUN_80010340((double)(float)param_2[0xbf],pfVar3);
    if ((((iVar1 != 0) || (pfVar3[4] != 0.0)) &&
        (cVar2 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar3), cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e3550,*param_2,param_1,&DAT_803dc920,0xffffffff),
       cVar2 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    FUN_8014d3f4((short *)param_1,param_2,0xf,0);
    local_28 = pfVar3[0x1a] - *(float *)(param_1 + 6);
    local_24 = pfVar3[0x1b] - *(float *)(param_1 + 8);
    local_20 = pfVar3[0x1c] - *(float *)(param_1 + 10);
    FUN_8014caf0((double)FLOAT_803e3554,(double)FLOAT_803e3558,(double)FLOAT_803e355c,(int)param_1,
                 (int)param_2,&local_28,'\x01');
    param_2[0xc9] = (float)param_2[0xc9] + FLOAT_803dc074;
    if (FLOAT_803e3560 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = FLOAT_803e3548;
    }
  }
  FUN_8014d194((double)FLOAT_803e3564,(double)FLOAT_803e3568,param_1,(int)param_2,0xf,'\0');
  param_2[0xca] = (float)param_2[0xca] - FLOAT_803dc074;
  if ((float)param_2[0xca] <= FLOAT_803e3548) {
    param_2[0xca] = FLOAT_803e354c;
    FUN_8000bb38((uint)param_1,0x25c);
  }
  param_2[0xcb] = FLOAT_803e3548;
  return;
}

