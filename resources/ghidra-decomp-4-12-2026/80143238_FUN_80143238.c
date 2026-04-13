// Function: FUN_80143238
// Entry: 80143238
// Size: 560 bytes

undefined4 FUN_80143238(int param_1,int *param_2)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined auStack_28 [8];
  float local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = FUN_80144994(param_1,param_2);
  if (iVar3 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x2e) {
      if (((param_2[0x15] & 0x8000000U) != 0) &&
         ((((param_2[0x15] & 0x10000U) != 0 || (uVar4 = FUN_80022264(0,2), uVar4 == 0)) ||
          (FLOAT_803e306c < (float)param_2[0x1c8])))) {
        FUN_8013a778((double)FLOAT_803e307c,param_1,0x2f,0);
      }
      local_1c = *(undefined4 *)(param_1 + 0x18);
      local_18 = *(undefined4 *)(param_1 + 0x1c);
      local_14 = *(undefined4 *)(param_1 + 0x20);
      local_20 = FLOAT_803e3080;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7e6,auStack_28,0x200001,0xffffffff,0);
    }
    else if (sVar1 < 0x2e) {
      if ((0x2b < sVar1) && ((param_2[0x15] & 0x8000000U) != 0)) {
        FUN_8013a778((double)FLOAT_803e312c,param_1,0x2e,0);
      }
    }
    else if ((sVar1 < 0x30) && ((param_2[0x15] & 0x8000000U) != 0)) {
      if (FLOAT_803e306c == (float)param_2[0xab]) {
        bVar2 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_2[0xac]) {
        bVar2 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e30a4) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
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

