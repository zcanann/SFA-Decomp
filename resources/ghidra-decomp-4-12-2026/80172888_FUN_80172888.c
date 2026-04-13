// Function: FUN_80172888
// Entry: 80172888
// Size: 676 bytes

void FUN_80172888(short *param_1)

{
  short sVar1;
  ushort uVar2;
  uint uVar3;
  float *pfVar4;
  undefined8 local_18;
  undefined8 local_10;
  
  pfVar4 = *(float **)(param_1 + 0x5c);
  sVar1 = param_1[0x23];
  if (sVar1 != 0x137) {
    if (sVar1 < 0x137) {
      if (sVar1 != 0x12d) {
        if (sVar1 < 0x12d) {
          if (sVar1 == 0x22) {
            local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
            *param_1 = (short)(int)(FLOAT_803e4114 * FLOAT_803dc074 +
                                   (float)(local_10 - DOUBLE_803e40e0));
            FUN_80099c40((double)FLOAT_803e40ec,param_1,10,1);
            return;
          }
          if (0x21 < sVar1) {
            return;
          }
          if (sVar1 != 0xb) {
            return;
          }
          sVar1 = *(short *)(pfVar4 + 0xd);
          uVar2 = (ushort)DAT_803dc070;
          *(ushort *)(pfVar4 + 0xd) = sVar1 - uVar2;
          if ((short)(sVar1 - uVar2) < 1) {
            uVar3 = FUN_80022264(600,800);
            local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
            pfVar4[0xc] = (float)(local_18 - DOUBLE_803e40e0);
            uVar3 = FUN_80022264(0xb4,0xf0);
            *(short *)(pfVar4 + 0xd) = (short)uVar3;
            FUN_8000bb38((uint)param_1,0x169);
          }
          param_1[1] = (short)(int)pfVar4[0xc];
          pfVar4[0xc] = pfVar4[0xc] * FLOAT_803e4110;
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
        if (FLOAT_803e4114 <= *pfVar4) {
          return;
        }
        uVar3 = FUN_80022264(0,10);
        if (uVar3 == 0) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x423,0,2,0xffffffff,0);
        }
        *param_1 = *param_1 + (short)(int)(FLOAT_803e4118 * FLOAT_803dc074);
        return;
      }
      if (0x27e < sVar1) {
        if (sVar1 != 0x5e8) {
          return;
        }
        local_10 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
        *param_1 = (short)(int)(FLOAT_803e4114 * FLOAT_803dc074 +
                               (float)(local_10 - DOUBLE_803e40e0));
        FUN_80099c40((double)FLOAT_803e40ec,param_1,9,1);
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
  *param_1 = (short)(int)(FLOAT_803e4114 * FLOAT_803dc074 + (float)(local_18 - DOUBLE_803e40e0));
  return;
}

