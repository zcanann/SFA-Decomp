// Function: FUN_800894c8
// Entry: 800894c8
// Size: 620 bytes

void FUN_800894c8(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  byte bVar3;
  int iVar2;
  int iVar4;
  int *piVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  float local_48;
  float local_44;
  float local_40;
  int local_3c;
  float local_38;
  float local_34;
  float local_30;
  int local_2c;
  int local_28 [10];
  
  uVar10 = FUN_8028683c();
  fVar1 = FLOAT_803dfcd8;
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  pfVar6 = (float *)uVar10;
  iVar8 = 0;
  iVar7 = 0;
  if (DAT_803ddde4 == '\0') {
    if (DAT_803dddac == 0) {
      bVar3 = 0;
    }
    else {
      bVar3 = *(byte *)(DAT_803dddac + (uint)*(byte *)(iVar4 + 0xf2) * 0xa4 + 0xc1) >> 7;
    }
    if (bVar3 == 0) {
      if (DAT_803dddac == 0) {
        *pfVar6 = FLOAT_803dfcd8;
        *param_3 = FLOAT_803dfcec;
        *param_4 = fVar1;
      }
      else {
        iVar8 = (uint)*(byte *)(iVar4 + 0xf2) * 0xa4;
        *pfVar6 = *(float *)(DAT_803dddac + iVar8 + 0x90);
        *param_3 = *(float *)(DAT_803dddac + iVar8 + 0x94);
        *param_4 = *(float *)(DAT_803dddac + iVar8 + 0x98);
      }
    }
    else {
      FUN_8001ed58(iVar4,&local_2c,4,&local_3c,2);
      if (local_3c < 1) {
        iVar7 = 0;
        local_38 = FLOAT_803dfce8;
        local_34 = FLOAT_803dfcec;
        local_30 = FLOAT_803dfce8;
        FUN_80247ef8(&local_38,&local_38);
        *pfVar6 = local_38;
        *param_3 = local_34;
        *param_4 = local_30;
      }
      else {
        if (*(int *)(iVar4 + 100) != 0) {
          iVar8 = *(int *)(*(int *)(iVar4 + 100) + 0x3c);
        }
        iVar7 = local_2c;
        if ((iVar8 != local_2c) && (iVar8 != 0)) {
          piVar5 = local_28;
          iVar2 = local_3c + -1;
          if (1 < local_3c) {
            do {
              if (*piVar5 == iVar8) {
                if (-*(float *)(local_2c + 0x130) < FLOAT_803dfce4 * -*(float *)(iVar8 + 0x130)) {
                  iVar7 = iVar8;
                }
                break;
              }
              piVar5 = piVar5 + 1;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
        }
        FUN_8001de30(iVar7,&local_40,&local_44,&local_48);
        local_38 = *(float *)(iVar4 + 0x18) - local_40;
        local_34 = *(float *)(iVar4 + 0x1c) - local_44;
        local_30 = *(float *)(iVar4 + 0x20) - local_48;
        dVar9 = FUN_80247f54(&local_38);
        if ((double)FLOAT_803dfcd8 < dVar9) {
          FUN_80247edc((double)(float)((double)FLOAT_803dfcdc / dVar9),&local_38,&local_38);
          *pfVar6 = local_38;
          *param_3 = local_34;
          *param_4 = local_30;
        }
      }
    }
  }
  else {
    *pfVar6 = DAT_8039b408;
    *param_3 = DAT_8039b40c;
    *param_4 = DAT_8039b410;
  }
  if (*(int *)(iVar4 + 100) != 0) {
    *(int *)(*(int *)(iVar4 + 100) + 0x3c) = iVar7;
  }
  FUN_80286888();
  return;
}

