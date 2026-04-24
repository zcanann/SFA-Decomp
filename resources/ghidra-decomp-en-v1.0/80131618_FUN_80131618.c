// Function: FUN_80131618
// Entry: 80131618
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x80131650) */

void FUN_80131618(short *param_1,undefined4 param_2,uint param_3)

{
  byte bVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  
  bVar1 = *(byte *)((int)param_1 + 5);
  if (bVar1 == 1) {
    if ((*(byte *)(param_1 + 2) & 1) == 0) {
      if (param_1[6] == 0) {
        iVar4 = 5;
      }
      else {
        iVar4 = 3;
      }
    }
    else if (param_1[6] == 0) {
      iVar4 = 4;
    }
    else {
      iVar4 = 2;
    }
    if ((*(byte *)(param_1 + 2) & 0x20) == 0) {
      param_3 = param_3 & 0xff;
    }
    else {
      param_3 = (int)(param_3 & 0xff) >> 1;
    }
    FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e21e8),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                DOUBLE_803e21e8),(&DAT_803a9db8)[iVar4],param_3,0x100);
  }
  else if (bVar1 == 0) {
    FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e21e8),
                 (double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                DOUBLE_803e21e8),DAT_803a9dbc,(int)((param_3 & 0xff) * 0xb4) >> 8,
                 0x100);
    FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,
                                                  (int)(((float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_1[7] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e21e8) *
                                                         ((float)((double)CONCAT44(0x43300000,
                                                                                   (int)param_1[6] -
                                                                                   (int)param_1[4] ^
                                                                                   0x80000000) -
                                                                 DOUBLE_803e21e8) /
                                                         (float)((double)CONCAT44(0x43300000,
                                                                                  (int)param_1[5] -
                                                                                  (int)param_1[4] ^
                                                                                  0x80000000) -
                                                                DOUBLE_803e21e8)) +
                                                        (float)((double)CONCAT44(0x43300000,
                                                                                 (int)*param_1 ^
                                                                                 0x80000000) -
                                                               DOUBLE_803e21e8)) -
                                                       (float)((double)CONCAT44(0x43300000,
                                                                                (int)(uint)*(ushort 
                                                  *)(DAT_803a9db8 + 10) >> 1 ^ 0x80000000) -
                                                  DOUBLE_803e21e8)) ^ 0x80000000) - DOUBLE_803e21e8)
                 ,(double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] - 4U ^ 0x80000000) -
                                 DOUBLE_803e21e8),DAT_803a9db8,(int)((param_3 & 0xff) * 0xff) >> 8,
                 0x100);
  }
  else if (bVar1 < 3) {
    if ((*(byte *)(param_1 + 2) & 0x80) == 0) {
      iVar4 = (int)param_1[6];
    }
    else {
      iVar4 = 0;
    }
    uVar3 = FUN_800191c4(param_1[7],iVar4);
    FUN_80019908(0,0,0,(int)((param_3 & 0xff) * 0x96) >> 8);
    FUN_800198a4(param_1[8],2,2);
    FUN_8001618c(uVar3,param_1[8]);
    FUN_80019908(0xff,0xff,0xff,param_3);
    FUN_800198a4(param_1[8],0,0);
    FUN_8001618c(uVar3,param_1[8]);
  }
  cVar2 = *(char *)(param_1 + 3);
  *(char *)(param_1 + 3) = cVar2 + -1;
  if ((char)(cVar2 + -1) < '\0') {
    *(undefined *)(param_1 + 3) = 0;
  }
  return;
}

