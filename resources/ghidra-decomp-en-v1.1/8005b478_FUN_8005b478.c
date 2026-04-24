// Function: FUN_8005b478
// Entry: 8005b478
// Size: 404 bytes

/* WARNING: Removing unreachable block (ram,0x8005b5f0) */
/* WARNING: Removing unreachable block (ram,0x8005b5e8) */
/* WARNING: Removing unreachable block (ram,0x8005b490) */
/* WARNING: Removing unreachable block (ram,0x8005b488) */

int FUN_8005b478(undefined8 param_1,double param_2)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined8 local_30;
  
  dVar5 = (double)FUN_802925a0();
  iVar3 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar5 = (double)FUN_802925a0();
  iVar4 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((((-1 < iVar3) && (iVar3 < 0x10)) && (-1 < iVar4)) && (iVar4 < 0x10)) {
    iVar3 = iVar3 + iVar4 * 0x10;
    piVar2 = &DAT_80382f14;
    iVar4 = 5;
    do {
      iVar1 = (int)*(char *)(iVar3 + *piVar2);
      if (-1 < iVar1) {
        iVar1 = *(int *)(DAT_803ddb1c + iVar1 * 4);
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar1 + 0x8a) - 0x32U ^ 0x80000000);
        if (((double)(float)(local_30 - DOUBLE_803df840) < param_2) &&
           (local_30 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)(iVar1 + 0x8c) + 0x32U ^ 0x80000000),
           param_2 < (double)(float)(local_30 - DOUBLE_803df840))) {
          return (int)*(char *)(*piVar2 + iVar3);
        }
      }
      piVar2 = piVar2 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  return -1;
}

