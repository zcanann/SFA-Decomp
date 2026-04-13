// Function: FUN_80277238
// Entry: 80277238
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x802772c4) */

void FUN_80277238(int param_1,uint *param_2,byte param_3)

{
  uint uVar1;
  short sVar2;
  int iVar3;
  int unaff_r31;
  
  uVar1 = FUN_80277108(param_1,*param_2 >> 0x18,param_2[1] & 0xff);
  iVar3 = (int)(short)uVar1;
  if (param_3 == 4) {
    sVar2 = (short)(param_2[1] >> 8);
  }
  else {
    uVar1 = FUN_80277108(param_1,param_2[1] >> 8 & 0xff,param_2[1] >> 0x10 & 0xff);
    sVar2 = (short)uVar1;
  }
  if (param_3 == 2) {
    unaff_r31 = iVar3 * sVar2;
  }
  else {
    if (param_3 < 2) {
      if (param_3 != 0) {
        unaff_r31 = iVar3 - sVar2;
        goto LAB_80277318;
      }
    }
    else if (param_3 != 4) {
      if (param_3 < 4) {
        if (sVar2 == 0) {
          unaff_r31 = 0;
        }
        else {
          unaff_r31 = iVar3 / (int)sVar2;
        }
      }
      goto LAB_80277318;
    }
    unaff_r31 = iVar3 + sVar2;
  }
LAB_80277318:
  if (unaff_r31 < -0x8000) {
    sVar2 = -0x8000;
  }
  else if (unaff_r31 < 0x8000) {
    sVar2 = (short)unaff_r31;
  }
  else {
    sVar2 = 0x7fff;
  }
  FUN_802771d4(param_1,*param_2 >> 8 & 0xff,*param_2 >> 0x10 & 0xff,(int)sVar2);
  return;
}

