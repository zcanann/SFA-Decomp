// Function: FUN_801428ac
// Entry: 801428ac
// Size: 1264 bytes

void FUN_801428ac(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  float fVar2;
  uint uVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  undefined2 *puVar7;
  
  puVar7 = (undefined2 *)0x0;
  if ((param_10[0x15] & 0x10U) == 0) {
    if (*(char *)(param_10 + 500) != '\0') {
      if (*(char *)(param_10 + 500) == '\x01') {
        iVar6 = param_10[0x1f5];
        iVar5 = *(int *)(param_9 + 0x5c);
        if ((param_9[0x58] & 0x1000) == 0) {
          if ((*(uint *)(iVar5 + 0x54) & 0x10) == 0) {
            *(int *)(iVar5 + 0x24) = iVar6;
            if (*(int *)(iVar5 + 0x28) != iVar6 + 0x18) {
              *(int *)(iVar5 + 0x28) = iVar6 + 0x18;
              *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) & 0xfffffbff;
              *(undefined2 *)(iVar5 + 0xd2) = 0;
            }
            *(undefined *)(iVar5 + 10) = 0;
            *(undefined *)(iVar5 + 8) = 10;
          }
          else {
            *(undefined *)(iVar5 + 2000) = 1;
            *(int *)(iVar5 + 0x7d4) = iVar6;
            *(uint *)(iVar5 + 0x54) = *(uint *)(iVar5 + 0x54) | 0x10000;
          }
        }
        iVar5 = FUN_80144994((int)param_9,param_10);
        if ((iVar5 == 0) &&
           (iVar5 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,
                                 param_7,param_8,param_9,param_10,iVar6,param_12,param_13,param_14,
                                 param_15,param_16), iVar5 == 0)) {
          param_10[0x1d0] = (int)((float)param_10[0x1d0] - FLOAT_803dc074);
          if ((float)param_10[0x1d0] <= FLOAT_803e306c) {
            uVar3 = FUN_80022264(500,0x2ee);
            param_10[0x1d0] =
                 (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
            iVar5 = *(int *)(param_9 + 0x5c);
            if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < (short)param_9[0x50] || ((short)param_9[0x50] < 0x29)) &&
                (bVar4 = FUN_8000b598((int)param_9,0x10), !bVar4)))) {
              FUN_800394f0(param_9,iVar5 + 0x3a8,0x360,0x500,0xffffffff,0);
            }
          }
          if (FLOAT_803e306c == (float)param_10[0xab]) {
            bVar4 = false;
          }
          else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
            bVar4 = true;
          }
          else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
            bVar4 = false;
          }
          else {
            bVar4 = true;
          }
          if (bVar4) {
            FUN_8013a778((double)FLOAT_803e30cc,(int)param_9,8,0);
            param_10[0x1e7] = (int)FLOAT_803e30d0;
            param_10[0x20e] = (int)FLOAT_803e306c;
            FUN_80148ff0();
          }
          else {
            sVar1 = param_9[0x50];
            if (sVar1 != 0x31) {
              if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
                if ((param_10[0x15] & 0x8000000U) != 0) {
                  FUN_8013a778((double)FLOAT_803e30cc,(int)param_9,0x31,0);
                }
              }
              else {
                FUN_8013a778((double)FLOAT_803e30d4,(int)param_9,0xd,0);
              }
            }
            FUN_80148ff0();
          }
        }
      }
      *(undefined *)(param_10 + 500) = 0;
      return;
    }
    puVar7 = (undefined2 *)FUN_801451c8((int)param_9,(int)param_10);
  }
  if (puVar7 == (undefined2 *)0x0) {
    param_10[0x1c7] = (int)((float)param_10[0x1c7] - FLOAT_803dc074);
    if ((float)param_10[0x1c7] < FLOAT_803e306c) {
      param_10[0x1c7] = (int)FLOAT_803e306c;
    }
    FUN_80144ed8((int)param_9,(int)param_10);
    iVar5 = (*(code *)(&PTR_FUN_8031dfa4)[*(byte *)((int)param_10 + 10)])(param_9,param_10);
    if (iVar5 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_8013a778((double)FLOAT_803e30cc,(int)param_9,8,0);
        param_10[0x1e7] = (int)FLOAT_803e30d0;
        param_10[0x20e] = (int)FLOAT_803e306c;
      }
      else {
        FUN_8013a778((double)FLOAT_803e31a8,(int)param_9,0x25,0);
      }
    }
  }
  else {
    *(undefined *)(param_10 + 0xdd) = 2;
    (**(code **)(*DAT_803dd728 + 0x20))(param_9,param_10 + 0x3e);
    *(undefined *)(param_10 + 2) = 1;
    *(undefined *)((int)param_10 + 10) = 0;
    fVar2 = FLOAT_803e306c;
    param_10[0x1c7] = (int)FLOAT_803e306c;
    param_10[0x1c8] = (int)fVar2;
    param_10[0x15] = param_10[0x15] & 0xffffffef;
    param_10[0x15] = param_10[0x15] & 0xfffeffff;
    param_10[0x15] = param_10[0x15] & 0xfffdffff;
    param_10[0x15] = param_10[0x15] & 0xfffbffff;
    *(undefined *)((int)param_10 + 0xd) = 0xff;
    *(undefined4 *)(param_9 + 6) = *(undefined4 *)(puVar7 + 6);
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(puVar7 + 8);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(puVar7 + 10);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(puVar7 + 0xc);
    *(undefined4 *)(param_9 + 0xe) = *(undefined4 *)(puVar7 + 0xe);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(puVar7 + 0x10);
    FUN_80036084((int)param_9);
    *param_9 = *puVar7;
    *(undefined *)((int)param_10 + 9) = 0;
    fVar2 = FLOAT_803e306c;
    param_10[4] = (int)FLOAT_803e306c;
    param_10[5] = (int)fVar2;
    param_10[0x38] = *(int *)(puVar7 + 0xc);
    param_10[0x39] = *(int *)(puVar7 + 0xe);
    param_10[0x3a] = *(int *)(puVar7 + 0x10);
    param_10[0x15] = param_10[0x15] | 0x80000;
    param_10[0x15] = param_10[0x15] & 0xffffdfff;
  }
  return;
}

