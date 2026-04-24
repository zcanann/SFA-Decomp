// Function: FUN_8020a5e8
// Entry: 8020a5e8
// Size: 376 bytes

undefined4 FUN_8020a5e8(short *param_1,float *param_2)

{
  int iVar1;
  undefined4 uVar2;
  short sVar3;
  int iVar4;
  float local_28;
  float local_24;
  float local_20;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  FUN_80247794(param_1 + 0x12,&local_28);
  if (*(int *)(iVar4 + 0x168) == 0) {
    iVar4 = 0;
    if (local_24 <= FLOAT_803e6538) {
      if (FLOAT_803e653c <= local_24) {
        sVar3 = FUN_800217c0((double)local_28,(double)local_20);
        sVar3 = *param_1 - sVar3;
        if (0x8000 < sVar3) {
          sVar3 = sVar3 + 1;
        }
        if (sVar3 < -0x8000) {
          sVar3 = sVar3 + -1;
        }
        iVar1 = (int)sVar3;
        if (iVar1 < 0) {
          iVar1 = -iVar1;
        }
        if (0x2000 < iVar1) {
          iVar1 = (int)sVar3;
          if (iVar1 < 0) {
            iVar1 = -iVar1;
          }
          if (iVar1 < 0x6000) {
            if (sVar3 < 1) {
              iVar4 = 2;
            }
            else {
              iVar4 = 1;
            }
          }
        }
      }
      else {
        iVar4 = 4;
      }
    }
    else {
      iVar4 = 3;
    }
    uVar2 = (&DAT_80329f90)[iVar4];
    *param_2 = (float)((double)CONCAT44(0x43300000,(&DAT_80329fa4)[iVar4] ^ 0x80000000) -
                      DOUBLE_803e6528);
  }
  else {
    *param_2 = FLOAT_803e6534;
    uVar2 = *(undefined4 *)(iVar4 + 0x168);
  }
  return uVar2;
}

