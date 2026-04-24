// Function: FUN_8020ac20
// Entry: 8020ac20
// Size: 376 bytes

undefined4 FUN_8020ac20(short *param_1,float *param_2)

{
  short sVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  float local_28;
  float local_24;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  FUN_80247ef8((float *)(param_1 + 0x12),&local_28);
  if (*(int *)(iVar4 + 0x168) == 0) {
    iVar4 = 0;
    if (local_24 <= FLOAT_803e71d0) {
      if (FLOAT_803e71d4 <= local_24) {
        iVar3 = FUN_80021884();
        sVar1 = *param_1 - (short)iVar3;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        iVar3 = (int)sVar1;
        if (iVar3 < 0) {
          iVar3 = -iVar3;
        }
        if (0x2000 < iVar3) {
          iVar3 = (int)sVar1;
          if (iVar3 < 0) {
            iVar3 = -iVar3;
          }
          if (iVar3 < 0x6000) {
            if (sVar1 < 1) {
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
    uVar2 = (&DAT_8032abd0)[iVar4];
    *param_2 = (float)((double)CONCAT44(0x43300000,(&DAT_8032abe4)[iVar4] ^ 0x80000000) -
                      DOUBLE_803e71c0);
  }
  else {
    *param_2 = FLOAT_803e71cc;
    uVar2 = *(undefined4 *)(iVar4 + 0x168);
  }
  return uVar2;
}

