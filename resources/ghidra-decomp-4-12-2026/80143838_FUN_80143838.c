// Function: FUN_80143838
// Entry: 80143838
// Size: 804 bytes

undefined4 FUN_80143838(int param_1,int *param_2)

{
  char cVar1;
  short sVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  undefined auStack_28 [12];
  int local_1c;
  float local_18;
  int local_14;
  
  iVar5 = FUN_80144994(param_1,param_2);
  if (iVar5 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar2 = *(short *)(param_1 + 0xa0);
    if (sVar2 == 0x2a) {
      param_2[0x1cf] = (int)((float)param_2[0x1cf] - FLOAT_803dc074);
      if ((float)param_2[0x1cf] <= FLOAT_803e306c) {
        if (((param_2[0x15] & 0x10000U) != 0) || (FLOAT_803e306c < (float)param_2[0x1c8])) {
          FUN_8013a778((double)FLOAT_803e307c,param_1,0x2b,0);
        }
        else {
          iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
          if (iVar5 == 0) {
            FUN_8013a778((double)FLOAT_803e31ac,param_1,0x2c,0);
            *(undefined *)((int)param_2 + 10) = 9;
          }
        }
      }
      for (iVar5 = 0; iVar5 < *(char *)((int)param_2 + 0x827); iVar5 = iVar5 + 1) {
        cVar1 = *(char *)((int)param_2 + iVar5 + 0x81f);
        if (cVar1 == '\0') {
          FUN_800394f0(param_1,param_2 + 0xea,0x390,0x500,0xffffffff,0);
        }
        else if (cVar1 == '\a') {
          FUN_800394f0(param_1,param_2 + 0xea,0x391,0x100,0xffffffff,0);
        }
      }
      fVar3 = (float)param_2[0x1d1] - FLOAT_803dc074;
      param_2[0x1d1] = (int)fVar3;
      if (fVar3 <= FLOAT_803e306c) {
        if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
          local_1c = param_2[0x102];
          local_18 = FLOAT_803e3088 + (float)param_2[0x103];
          local_14 = param_2[0x104];
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f0,auStack_28,0x200001,0xffffffff,0);
        }
        param_2[0x1d1] = (int)FLOAT_803e3158;
      }
    }
    else if (sVar2 < 0x2a) {
      if ((0x28 < sVar2) && ((param_2[0x15] & 0x8000000U) != 0)) {
        FUN_8013a778((double)FLOAT_803e31b0,param_1,0x2a,0);
      }
    }
    else if ((sVar2 < 0x2c) && ((param_2[0x15] & 0x8000000U) != 0)) {
      if (FLOAT_803e306c == (float)param_2[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_2[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_8013a778((double)FLOAT_803e30cc,param_1,8,0);
        param_2[0x1e7] = (int)FLOAT_803e30d0;
        param_2[0x20e] = (int)FLOAT_803e306c;
        FUN_80148ff0();
      }
      else {
        FUN_8013a778((double)FLOAT_803e30d4,param_1,0,0);
        FUN_80148ff0();
      }
      param_2[0x15] = param_2[0x15] & 0xffffffef;
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}

