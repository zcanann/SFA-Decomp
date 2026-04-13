// Function: FUN_80104990
// Entry: 80104990
// Size: 612 bytes

void FUN_80104990(undefined4 param_1,undefined4 param_2,undefined param_3,float *param_4,
                 float *param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  undefined uVar9;
  int iVar8;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  ulonglong uVar13;
  int local_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  uint auStack_30 [12];
  
  uVar13 = FUN_80286840();
  iVar7 = (int)(uVar13 >> 0x20);
  uVar11 = *(undefined4 *)(iVar7 + 0xa4);
  if ((uVar13 & 1) != 0) {
    *(float *)(iVar7 + 0x74) = FLOAT_803e2308;
    *(undefined *)(iVar7 + 0x84) = 0xff;
    *(undefined *)(iVar7 + 0x88) = param_3;
    uVar9 = FUN_80064248(iVar7 + 0xb8,iVar7 + 0x18,(float *)0x1,(int *)0x0,(int *)0x0,0x10,
                         0xffffffff,0xff,0);
    *(undefined *)(iVar7 + 0x142) = uVar9;
    local_3c = *(float *)(iVar7 + 0x18);
    local_38 = *(undefined4 *)(iVar7 + 0x1c);
    local_34 = *(undefined4 *)(iVar7 + 0x20);
    FUN_80069798(auStack_30,(float *)(iVar7 + 0xb8),&local_3c,(float *)(iVar7 + 0x74),1);
    FUN_8006933c(uVar11,auStack_30,0x240,'\x01');
    FUN_80067ad4();
    *(float *)(iVar7 + 0x18) = local_3c;
    *(undefined4 *)(iVar7 + 0x1c) = local_38;
    *(undefined4 *)(iVar7 + 0x20) = local_34;
  }
  if ((uVar13 & 2) != 0) {
    iVar8 = FUN_80065fcc((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
                         (double)*(float *)(iVar7 + 0x20),uVar11,&local_40,1,0x40);
    *param_4 = FLOAT_803e2350;
    fVar5 = FLOAT_803e2354;
    *param_5 = FLOAT_803e2354;
    fVar2 = FLOAT_803e2334;
    fVar6 = FLOAT_803e232c;
    iVar10 = 0;
    iVar12 = iVar8;
    fVar3 = fVar5;
    if (0 < iVar8) {
      do {
        if ((*(float **)(local_40 + iVar10))[2] < fVar6) {
          fVar1 = **(float **)(local_40 + iVar10);
          if (*(float *)(iVar7 + 0x1c) - fVar2 < fVar1) {
            fVar4 = *(float *)(iVar7 + 0x1c) - fVar1;
            if (fVar4 < fVar6) {
              fVar4 = -fVar4;
            }
            if (fVar4 < fVar3) {
              *param_5 = fVar1;
              *(undefined4 *)(iVar7 + 300) = *(undefined4 *)(*(int *)(local_40 + iVar10) + 8);
              fVar3 = fVar4;
            }
          }
        }
        iVar10 = iVar10 + 4;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
    fVar6 = FLOAT_803e2334;
    fVar3 = FLOAT_803e232c;
    iVar12 = 0;
    if (0 < iVar8) {
      do {
        if (fVar3 < (*(float **)(local_40 + iVar12))[2]) {
          fVar2 = **(float **)(local_40 + iVar12);
          if (fVar2 < fVar6 + *(float *)(iVar7 + 0x1c)) {
            fVar1 = *(float *)(iVar7 + 0x1c) - fVar2;
            if (fVar1 < fVar3) {
              fVar1 = -fVar1;
            }
            if (fVar1 < fVar5) {
              *param_4 = fVar2;
              *(undefined4 *)(iVar7 + 0x130) = *(undefined4 *)(*(int *)(local_40 + iVar12) + 8);
              fVar5 = fVar1;
            }
          }
        }
        iVar12 = iVar12 + 4;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
  }
  FUN_8000e054((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
               (double)*(float *)(iVar7 + 0x20),(float *)(iVar7 + 0xc),(float *)(iVar7 + 0x10),
               (float *)(iVar7 + 0x14),*(int *)(iVar7 + 0x30));
  FUN_8028688c();
  return;
}

