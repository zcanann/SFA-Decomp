// Function: FUN_802086c4
// Entry: 802086c4
// Size: 1196 bytes

/* WARNING: Removing unreachable block (ram,0x80208b40) */
/* WARNING: Removing unreachable block (ram,0x80208b48) */

void FUN_802086c4(int param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined4 local_58;
  int local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_58 = 0xffffffff;
  iVar6 = *(int *)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x46) == 0x4e0) {
    FLOAT_803ddcf8 = *(float *)(param_1 + 0xc);
    FLOAT_803ddcfc = *(float *)(param_1 + 0x14);
  }
  else if ((((*(char *)(iVar6 + 0x6b) == '\0') && (*(char *)(iVar6 + 0x6a) != '\0')) &&
           (*(char *)(iVar6 + 0x69) != '\x04')) && (*(char *)(iVar6 + 0x69) != '\x03')) {
    *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
    local_54 = 0;
    iVar3 = FUN_8003687c(param_1,&local_54,&local_58,0);
    if (((iVar3 != 0) && (local_54 != 0)) && ((iVar3 == 0xe && (iVar3 == 0xe)))) {
      FUN_8000bb18(param_1,0x44d);
      fVar1 = *(float *)(local_54 + 0x24);
      fVar2 = *(float *)(local_54 + 0x2c);
      if (fVar1 < FLOAT_803e648c) {
        fVar1 = fVar1 * FLOAT_803e6494;
      }
      if (fVar2 < FLOAT_803e648c) {
        fVar2 = fVar2 * FLOAT_803e6494;
      }
      if (fVar1 <= fVar2) {
        *(float *)(local_54 + 0x24) = FLOAT_803e648c;
      }
      else {
        *(float *)(local_54 + 0x2c) = FLOAT_803e648c;
      }
      fVar1 = FLOAT_803e6498;
      *(float *)(param_1 + 0x24) = *(float *)(local_54 + 0x24) * FLOAT_803e6498;
      *(float *)(param_1 + 0x2c) = *(float *)(local_54 + 0x2c) * fVar1;
    }
    *(float *)(param_1 + 0xc) =
         *(float *)(param_1 + 0x24) * FLOAT_803db414 + *(float *)(param_1 + 0xc);
    *(float *)(param_1 + 0x14) =
         *(float *)(param_1 + 0x2c) * FLOAT_803db414 + *(float *)(param_1 + 0x14);
    if (FLOAT_803e648c != *(float *)(param_1 + 0x24)) {
      FUN_8000da58(param_1,0x3bd);
      fVar1 = *(float *)(param_1 + 0x24);
      if (FLOAT_803e648c <= fVar1) {
        if ((FLOAT_803e648c < fVar1) && (fVar1 <= FLOAT_803e648c)) {
          *(float *)(param_1 + 0x24) = FLOAT_803e648c;
        }
      }
      else if (FLOAT_803e648c <= fVar1) {
        *(float *)(param_1 + 0x24) = FLOAT_803e648c;
      }
    }
    if (FLOAT_803e648c != *(float *)(param_1 + 0x2c)) {
      FUN_8000da58(param_1,0x3bd);
      fVar1 = *(float *)(param_1 + 0x2c);
      if (FLOAT_803e648c <= fVar1) {
        if ((FLOAT_803e648c < fVar1) && (fVar1 <= FLOAT_803e648c)) {
          *(float *)(param_1 + 0x2c) = FLOAT_803e648c;
        }
      }
      else if (FLOAT_803e648c <= fVar1) {
        *(float *)(param_1 + 0x2c) = FLOAT_803e648c;
      }
    }
    FUN_80208508(param_1,iVar6);
    dVar9 = (double)(*(float *)(iVar5 + 8) - *(float *)(param_1 + 0xc));
    dVar8 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(param_1 + 0x14));
    cVar4 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
    if (cVar4 == '\x01') {
      if ((((double)FLOAT_803e649c < dVar9) || (dVar9 < (double)FLOAT_803e64a0)) ||
         ((dVar8 < (double)FLOAT_803e64a4 || ((double)FLOAT_803e64a8 < dVar8)))) {
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar5 + 8);
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e648c;
        *(float *)(param_1 + 0x24) = FLOAT_803e648c;
        *(float *)(param_1 + 0x2c) = fVar1;
        *(undefined *)(iVar6 + 0x69) = 2;
        *(float *)(param_1 + 0x10) = *(float *)(iVar5 + 0xc) - FLOAT_803e64ac;
        FUN_8000bb18(param_1,0x1d3);
      }
      fVar1 = *(float *)(param_1 + 0xc) - FLOAT_803ddcf8;
      fVar2 = *(float *)(param_1 + 0x14) - FLOAT_803ddcfc;
      if ((FLOAT_803e648c == fVar1) && (FLOAT_803e648c == fVar2)) {
        *(undefined *)(iVar6 + 0x69) = 3;
      }
      else {
        dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar8 < (double)FLOAT_803e64b0) {
          *(undefined *)(iVar6 + 0x69) = 3;
        }
      }
    }
    else if (cVar4 == '\x02') {
      if (((((double)FLOAT_803e64b4 < dVar9) || (dVar9 < (double)FLOAT_803e64b8)) ||
          (dVar8 < (double)FLOAT_803e64a4)) || ((double)FLOAT_803e64bc < dVar8)) {
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar5 + 8);
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar5 + 0x10);
        fVar1 = FLOAT_803e648c;
        *(float *)(param_1 + 0x24) = FLOAT_803e648c;
        *(float *)(param_1 + 0x2c) = fVar1;
        *(undefined *)(iVar6 + 0x69) = 2;
        *(float *)(param_1 + 0x10) = *(float *)(iVar5 + 0xc) - FLOAT_803e64ac;
        FUN_8000bb18(param_1,0x1d3);
        local_44 = *(undefined4 *)(param_1 + 0xc);
        local_40 = *(undefined4 *)(param_1 + 0x10);
        local_3c = *(undefined4 *)(param_1 + 0x14);
        local_48 = FLOAT_803e6490;
        local_4c = 0;
        local_4e = 0;
        local_50 = 0;
        iVar5 = 0x14;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x5f5,&local_50,0x200001,0xffffffff,0);
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      fVar1 = *(float *)(param_1 + 0xc) - FLOAT_803ddcf8;
      fVar2 = *(float *)(param_1 + 0x14) - FLOAT_803ddcfc;
      if ((FLOAT_803e648c == fVar1) && (FLOAT_803e648c == fVar2)) {
        *(undefined *)(iVar6 + 0x69) = 3;
      }
      else {
        dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
        if (dVar8 < (double)FLOAT_803e64c0) {
          *(undefined *)(iVar6 + 0x69) = 3;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  return;
}

