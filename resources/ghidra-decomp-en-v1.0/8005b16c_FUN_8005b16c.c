// Function: FUN_8005b16c
// Entry: 8005b16c
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x8005b2e0) */

undefined4 FUN_8005b16c(double param_1,double param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar5 = (double)FUN_80291e40((double)(float)(param_1 / (double)FLOAT_803debb4));
  iVar3 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd0 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  dVar5 = (double)FUN_80291e40((double)(float)(param_2 / (double)FLOAT_803debb4));
  iVar1 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcdd4 ^ 0x80000000) -
                                       DOUBLE_803debc0));
  if ((iVar3 < 0) || (0xf < iVar3)) {
    uVar2 = 0xffffffff;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = iVar3 + iVar1 * 0x10;
    if (*(char *)(iVar3 + DAT_803822b4) < '\0') {
      if (*(char *)(iVar3 + DAT_803822b8) < '\0') {
        if (*(char *)(iVar3 + DAT_803822bc) < '\0') {
          if (*(char *)(iVar3 + DAT_803822c0) < '\0') {
            if (*(char *)(iVar3 + DAT_803822c4) < '\0') {
              uVar2 = 0;
            }
            else {
              uVar2 = 1;
            }
          }
          else {
            uVar2 = 1;
          }
        }
        else {
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = 1;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return uVar2;
}

