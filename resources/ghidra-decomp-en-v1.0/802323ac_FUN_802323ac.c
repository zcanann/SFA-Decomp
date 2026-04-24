// Function: FUN_802323ac
// Entry: 802323ac
// Size: 720 bytes

void FUN_802323ac(int param_1,int param_2)

{
  double dVar1;
  int iVar2;
  undefined local_38 [3];
  char cStack53;
  undefined auStack52 [4];
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  if (*(int *)(param_1 + 0x54) != 0) {
    if (*(char *)(param_2 + 0x154) != '\0') {
      *(float *)(param_2 + 0x110) = *(float *)(param_2 + 0x110) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x110) <= FLOAT_803e7168) {
        *(undefined *)(param_2 + 0x154) = 0;
      }
      dVar1 = DOUBLE_803e7180;
      if ((*(byte *)(param_2 + 0x160) >> 4 & 1) != 0) {
        uStack44 = (uint)*(ushort *)(param_2 + 0x150);
        local_30 = 0x43300000;
        iVar2 = (int)(FLOAT_803e71ac * FLOAT_803db414 +
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7180));
        local_28 = (longlong)iVar2;
        *(short *)(param_2 + 0x150) = (short)iVar2;
        uStack28 = (uint)*(ushort *)(param_2 + 0x152);
        local_20 = 0x43300000;
        iVar2 = (int)(FLOAT_803e71b0 * FLOAT_803db414 +
                     (float)((double)CONCAT44(0x43300000,uStack28) - dVar1));
        local_18 = (longlong)iVar2;
        *(short *)(param_2 + 0x152) = (short)iVar2;
      }
    }
    iVar2 = FUN_8003687c(param_1,auStack52,0,local_38);
    if ((iVar2 != 0) || (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0)) {
      if ((*(byte *)(param_2 + 0x160) >> 4 & 1) == 0) {
        if (*(char *)(param_2 + 0x154) == '\0') {
          FUN_8000b4d0(param_1,0x2b3,4);
        }
        *(float *)(param_2 + 0x110) = FLOAT_803e71b4;
        *(undefined *)(param_2 + 0x154) = 1;
      }
      else {
        if (*(char *)(param_2 + 0x154) == '\0') {
          FUN_8000b4d0(param_1,0x29e,4);
        }
        FUN_8002ac30(param_1,0xf,200,0,0,1);
        *(float *)(param_2 + 0x110) = FLOAT_803e71b4;
        *(undefined *)(param_2 + 0x154) = 1;
        *(undefined2 *)(param_2 + 0x150) = 0;
        *(undefined2 *)(param_2 + 0x152) = 0;
        *(char *)(param_2 + 0x15e) = *(char *)(param_2 + 0x15e) - cStack53;
        if (*(char *)(param_2 + 0x15e) < '\x01') {
          FUN_8008016c(param_2 + 300);
          FUN_80080178(param_2 + 300,0x78);
          if (*(char *)(param_2 + 0x15c) == '\x01') {
            FUN_8009ab70((double)FLOAT_803e719c,param_1,1,0,1,1,0,0,0);
            *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
            FUN_80035f00(param_1);
            *(undefined *)(param_2 + 0x159) = 4;
            *(undefined *)(param_2 + 0x159) = 3;
            if (*(char *)(param_2 + 0x15d) == '\x03') {
              FUN_80125ba4(0xe);
            }
          }
          else {
            FUN_8009ab70((double)FLOAT_803e719c,param_1,1,0,0,1,0,0,3);
            *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
            FUN_80035f00(param_1);
            *(undefined *)(param_2 + 0x159) = 3;
          }
          iVar2 = FUN_8022d768();
          if (iVar2 != 0) {
            FUN_8022d520(iVar2,*(undefined *)(param_2 + 0x157));
          }
        }
        else {
          iVar2 = FUN_8022d768();
          if (iVar2 != 0) {
            FUN_8022d520(iVar2,*(undefined *)(param_2 + 0x158));
          }
        }
      }
    }
  }
  return;
}

