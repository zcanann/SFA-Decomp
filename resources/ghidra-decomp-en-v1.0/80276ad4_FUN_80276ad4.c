// Function: FUN_80276ad4
// Entry: 80276ad4
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x80276b60) */

void FUN_80276ad4(undefined4 param_1,uint *param_2,byte param_3)

{
  short sVar1;
  int iVar2;
  int unaff_r31;
  
  sVar1 = FUN_802769a4(param_1,*param_2 >> 0x18,param_2[1] & 0xff);
  iVar2 = (int)sVar1;
  if (param_3 == 4) {
    sVar1 = (short)(param_2[1] >> 8);
  }
  else {
    sVar1 = FUN_802769a4(param_1,param_2[1] >> 8 & 0xff,param_2[1] >> 0x10 & 0xff);
  }
  if (param_3 == 2) {
    unaff_r31 = iVar2 * sVar1;
  }
  else {
    if (param_3 < 2) {
      if (param_3 != 0) {
        unaff_r31 = iVar2 - sVar1;
        goto LAB_80276bb4;
      }
    }
    else if (param_3 != 4) {
      if (param_3 < 4) {
        if (sVar1 == 0) {
          unaff_r31 = 0;
        }
        else {
          unaff_r31 = iVar2 / (int)sVar1;
        }
      }
      goto LAB_80276bb4;
    }
    unaff_r31 = iVar2 + sVar1;
  }
LAB_80276bb4:
  if (unaff_r31 < -0x8000) {
    sVar1 = -0x8000;
  }
  else if (unaff_r31 < 0x8000) {
    sVar1 = (short)unaff_r31;
  }
  else {
    sVar1 = 0x7fff;
  }
  FUN_80276a70(param_1,*param_2 >> 8 & 0xff,*param_2 >> 0x10 & 0xff,(int)sVar1);
  return;
}

