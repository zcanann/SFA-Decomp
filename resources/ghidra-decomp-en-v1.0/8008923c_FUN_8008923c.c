// Function: FUN_8008923c
// Entry: 8008923c
// Size: 620 bytes

void FUN_8008923c(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  byte bVar2;
  int iVar3;
  int *piVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  float local_48;
  float local_44;
  float local_40;
  int local_3c;
  float local_38;
  float local_34;
  float local_30;
  int local_2c;
  int local_28 [10];
  
  uVar9 = FUN_802860d8();
  fVar1 = FLOAT_803df058;
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  pfVar5 = (float *)uVar9;
  iVar7 = 0;
  iVar6 = 0;
  if (DAT_803dd164 == '\0') {
    if (DAT_803dd12c == 0) {
      bVar2 = 0;
    }
    else {
      bVar2 = *(byte *)(DAT_803dd12c + (uint)*(byte *)(iVar3 + 0xf2) * 0xa4 + 0xc1) >> 7;
    }
    if (bVar2 == 0) {
      if (DAT_803dd12c == 0) {
        *pfVar5 = FLOAT_803df058;
        *param_3 = FLOAT_803df06c;
        *param_4 = fVar1;
      }
      else {
        iVar7 = (uint)*(byte *)(iVar3 + 0xf2) * 0xa4;
        *pfVar5 = *(float *)(DAT_803dd12c + iVar7 + 0x90);
        *param_3 = *(float *)(DAT_803dd12c + iVar7 + 0x94);
        *param_4 = *(float *)(DAT_803dd12c + iVar7 + 0x98);
      }
    }
    else {
      FUN_8001ec94(iVar3,&local_2c,4,&local_3c,2);
      if (local_3c < 1) {
        iVar6 = 0;
        local_38 = FLOAT_803df068;
        local_34 = FLOAT_803df06c;
        local_30 = FLOAT_803df068;
        FUN_80247794(&local_38,&local_38);
        *pfVar5 = local_38;
        *param_3 = local_34;
        *param_4 = local_30;
      }
      else {
        if (*(int *)(iVar3 + 100) != 0) {
          iVar7 = *(int *)(*(int *)(iVar3 + 100) + 0x3c);
        }
        if ((iVar7 != local_2c) && (iVar7 != 0)) {
          piVar4 = local_28;
          iVar6 = local_3c + -1;
          if (1 < local_3c) {
            do {
              if (*piVar4 == iVar7) {
                if (-*(float *)(local_2c + 0x130) < FLOAT_803df064 * -*(float *)(iVar7 + 0x130)) {
                  local_2c = iVar7;
                }
                break;
              }
              piVar4 = piVar4 + 1;
              iVar6 = iVar6 + -1;
            } while (iVar6 != 0);
          }
        }
        FUN_8001dd6c(local_2c,&local_40,&local_44,&local_48);
        local_38 = *(float *)(iVar3 + 0x18) - local_40;
        local_34 = *(float *)(iVar3 + 0x1c) - local_44;
        local_30 = *(float *)(iVar3 + 0x20) - local_48;
        dVar8 = (double)FUN_802477f0(&local_38);
        iVar6 = local_2c;
        if ((double)FLOAT_803df058 < dVar8) {
          FUN_80247778((double)(float)((double)FLOAT_803df05c / dVar8),&local_38,&local_38);
          *pfVar5 = local_38;
          *param_3 = local_34;
          *param_4 = local_30;
        }
      }
    }
  }
  else {
    *pfVar5 = DAT_8039a7a8;
    *param_3 = DAT_8039a7ac;
    *param_4 = DAT_8039a7b0;
  }
  if (*(int *)(iVar3 + 100) != 0) {
    *(int *)(*(int *)(iVar3 + 100) + 0x3c) = iVar6;
  }
  FUN_80286124();
  return;
}

