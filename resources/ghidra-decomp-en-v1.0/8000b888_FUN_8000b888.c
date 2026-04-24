// Function: FUN_8000b888
// Entry: 8000b888
// Size: 276 bytes

/* WARNING: Removing unreachable block (ram,0x8000b97c) */

void FUN_8000b888(double param_1,int param_2,uint param_3,char param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (((param_3 & 0xff) == 0) || (param_2 == 0)) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1 = (undefined4 *)FUN_8000ccec(param_2,param_3,0,2);
  }
  if (puVar1 != (undefined4 *)0x0) {
    if (param_4 != -2) {
      if (param_4 == -1) {
        param_4 = 'd';
      }
      *(char *)((int)puVar1 + 7) = param_4;
      if (*(char *)(puVar1 + 1) == '\0') {
        if (*(char *)((int)puVar1 + 6) != '\0') {
          param_4 = '\0';
        }
        FUN_802727a8(*puVar1,7,param_4);
      }
      else {
        FUN_8000c6c0(puVar1);
      }
    }
    if (param_1 < (double)FLOAT_803de570) {
      param_1 = (double)FLOAT_803de570;
    }
    if ((double)FLOAT_803de574 < param_1) {
      param_1 = (double)FLOAT_803de574;
    }
    FUN_80272808(*puVar1,0x80,(int)((double)FLOAT_803de578 * param_1));
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

