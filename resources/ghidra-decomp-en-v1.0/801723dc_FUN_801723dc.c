// Function: FUN_801723dc
// Entry: 801723dc
// Size: 676 bytes

void FUN_801723dc(short *param_1)

{
  short sVar1;
  ushort uVar2;
  uint uVar3;
  undefined2 uVar5;
  int iVar4;
  float *pfVar6;
  double local_18;
  double local_10;
  
  pfVar6 = *(float **)(param_1 + 0x5c);
  sVar1 = param_1[0x23];
  if (sVar1 != 0x137) {
    if (sVar1 < 0x137) {
      if (sVar1 != 0x12d) {
        if (sVar1 < 0x12d) {
          if (sVar1 == 0x22) {
            local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
            *param_1 = (short)(int)(FLOAT_803e347c * FLOAT_803db414 +
                                   (float)(local_10 - DOUBLE_803e3448));
            FUN_800999b4((double)FLOAT_803e3454,param_1,10,1);
            return;
          }
          if (0x21 < sVar1) {
            return;
          }
          if (sVar1 != 0xb) {
            return;
          }
          sVar1 = *(short *)(pfVar6 + 0xd);
          uVar2 = (ushort)DAT_803db410;
          *(ushort *)(pfVar6 + 0xd) = sVar1 - uVar2;
          if ((short)(sVar1 - uVar2) < 1) {
            uVar3 = FUN_800221a0(600,800);
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            pfVar6[0xc] = (float)(local_18 - DOUBLE_803e3448);
            uVar5 = FUN_800221a0(0xb4,0xf0);
            *(undefined2 *)(pfVar6 + 0xd) = uVar5;
            FUN_8000bb18(param_1,0x169);
          }
          param_1[1] = (short)(int)pfVar6[0xc];
          pfVar6[0xc] = pfVar6[0xc] * FLOAT_803e3478;
          if (9 < param_1[1]) {
            return;
          }
          if (param_1[1] < -9) {
            return;
          }
          param_1[1] = 0;
          return;
        }
        if (sVar1 != 0x135) {
          return;
        }
      }
    }
    else {
      if (sVar1 == 0x27f) {
        if (FLOAT_803e347c <= *pfVar6) {
          return;
        }
        iVar4 = FUN_800221a0(0,10);
        if (iVar4 == 0) {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x423,0,2,0xffffffff,0);
        }
        *param_1 = *param_1 + (short)(int)(FLOAT_803e3480 * FLOAT_803db414);
        return;
      }
      if (0x27e < sVar1) {
        if (sVar1 != 0x5e8) {
          return;
        }
        local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
        *param_1 = (short)(int)(FLOAT_803e347c * FLOAT_803db414 +
                               (float)(local_10 - DOUBLE_803e3448));
        FUN_800999b4((double)FLOAT_803e3454,param_1,9,1);
        return;
      }
      if (sVar1 != 0x246) {
        if (0x245 < sVar1) {
          return;
        }
        if (sVar1 != 0x156) {
          return;
        }
      }
    }
  }
  local_18 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
  *param_1 = (short)(int)(FLOAT_803e347c * FLOAT_803db414 + (float)(local_18 - DOUBLE_803e3448));
  return;
}

