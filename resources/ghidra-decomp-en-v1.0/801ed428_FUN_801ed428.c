// Function: FUN_801ed428
// Entry: 801ed428
// Size: 1700 bytes

void FUN_801ed428(undefined2 *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  char cVar5;
  undefined4 uVar4;
  int iVar6;
  double dVar7;
  undefined auStack264 [4];
  undefined auStack260 [4];
  float local_100;
  float local_fc;
  undefined auStack248 [4];
  float local_f4;
  float local_f0;
  undefined auStack236 [4];
  short local_e8;
  short local_e6;
  short local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  short local_d0;
  short local_ce;
  short local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  undefined auStack184 [64];
  undefined auStack120 [64];
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  longlong local_10;
  
  iVar6 = *(int *)(param_1 + 0x5c);
  if (*(char *)(param_1 + 0x56) == -1) {
    iVar3 = FUN_8001ffb4(0x1fa);
    if (iVar3 != 0) {
      *(undefined *)(iVar6 + 0x420) = 0;
    }
    iVar3 = FUN_8001ffb4(0x1fb);
    if (iVar3 != 0) {
      FUN_8002a7fc(param_1,0x13);
    }
  }
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  param_1[1] = *(undefined2 *)(iVar6 + 0x41c);
  param_1[2] = *(undefined2 *)(iVar6 + 0x41e);
  if (((*(byte *)(iVar6 + 0x428) >> 2 & 1) == 0) &&
     (iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x44a)), iVar3 == 0)) {
    cVar5 = *(char *)(iVar6 + 0x421);
    if (cVar5 != '\x01') {
      if (cVar5 < '\x01') {
        if (-1 < cVar5) {
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
          if ((*(byte *)((int)param_1 + 0xaf) & 4) == 0) {
            *(undefined *)(iVar6 + 0x420) = 0;
          }
          else {
            *(undefined *)(iVar6 + 0x420) = 1;
          }
          FUN_8000b7bc(param_1,0x57);
        }
      }
      else if (cVar5 < '\x03') {
        FUN_801eae4c(param_1,iVar6);
        if ((*(byte *)(iVar6 + 0x428) >> 1 & 1) == 0) {
          FUN_8011f3ec(0x10);
          FUN_8011f3c8(0x11);
          cVar5 = FUN_80014cc0(0);
          uStack52 = (int)cVar5 ^ 0x80000000;
          local_38 = 0x43300000;
          *(float *)(iVar6 + 0x45c) =
               (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e5b00);
          cVar5 = FUN_80014c6c(0);
          uStack44 = (int)cVar5 ^ 0x80000000;
          local_30 = 0x43300000;
          iVar3 = (int)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5b00);
          local_28 = (longlong)iVar3;
          *(char *)(iVar6 + 0x460) = (char)iVar3;
          uVar4 = FUN_80014ee8(0);
          *(undefined4 *)(iVar6 + 0x458) = uVar4;
          uVar4 = FUN_80014e70(0);
          *(undefined4 *)(iVar6 + 0x450) = uVar4;
          uVar4 = FUN_80014e14(0);
          *(undefined4 *)(iVar6 + 0x454) = uVar4;
          uStack28 = -(int)*(char *)(iVar6 + 0x460) ^ 0x80000000;
          local_20 = 0x43300000;
          uStack20 = FUN_800217c0((double)*(float *)(iVar6 + 0x45c),
                                  (double)(float)((double)CONCAT44(0x43300000,uStack28) -
                                                 DOUBLE_803e5b00));
          uStack20 = uStack20 & 0xffff;
          local_18 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5c20) /
                       FLOAT_803e5c18);
          local_10 = (longlong)iVar3;
          *(short *)(iVar6 + 0x44c) = (short)iVar3;
          *(float *)(iVar6 + 0x45c) = *(float *)(iVar6 + 0x45c) / FLOAT_803e5b6c;
          fVar1 = *(float *)(iVar6 + 0x45c);
          fVar2 = FLOAT_803e5b70;
          if ((FLOAT_803e5b70 <= fVar1) && (fVar2 = fVar1, FLOAT_803e5aec < fVar1)) {
            fVar2 = FLOAT_803e5aec;
          }
          *(float *)(iVar6 + 0x45c) = fVar2;
          FUN_801ebd60(param_1,iVar6);
          FUN_801ec7a0(param_1,iVar6);
          if (*(float *)(iVar6 + 0x3e4) == FLOAT_803e5ae8) {
            *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
            *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
            *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
          }
          else {
            FUN_80247778((double)*(float *)(iVar6 + 0x3e0),iVar6 + 0x464,iVar6 + 0x47c);
            FUN_80247778((double)*(float *)(iVar6 + 0x3e0),iVar6 + 0x494,iVar6 + 0x494);
            *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - FLOAT_803db414;
            if (*(float *)(iVar6 + 0x3e4) <= FLOAT_803e5ae8) {
              iVar3 = FUN_800550bc();
              if (iVar3 != 0) {
                FUN_800550c4((double)FLOAT_803e5ae8,0);
              }
              *(float *)(iVar6 + 0x3e4) = FLOAT_803e5ae8;
            }
          }
          local_dc = FLOAT_803e5ae8;
          local_d8 = FLOAT_803e5ae8;
          local_d4 = FLOAT_803e5ae8;
          local_e0 = FLOAT_803e5aec;
          local_e8 = -*(short *)(iVar6 + 0x40e);
          local_e6 = -param_1[1];
          local_e4 = -param_1[2];
          FUN_80021ba0(auStack184,&local_e8);
          FUN_800226cc((double)FLOAT_803e5ae8,
                       (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                       (double)FLOAT_803e5ae8,auStack184,&local_100,auStack264,auStack248);
          local_100 = local_100 * *(float *)(iVar6 + 0x540);
          local_fc = FLOAT_803e5ae8;
          FUN_80247778((double)FLOAT_803db414,&local_100,&local_100);
          FUN_80247730(iVar6 + 0x494,&local_100,iVar6 + 0x494);
          *(float *)(iVar6 + 0x498) =
               *(float *)(iVar6 + 0x4b0) * FLOAT_803db414 + *(float *)(iVar6 + 0x498);
          dVar7 = (double)FUN_80292b44((double)*(float *)(iVar6 + 0x548),(double)FLOAT_803db414);
          *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
          dVar7 = (double)FUN_80292b44((double)*(float *)(iVar6 + 0x54c),(double)FLOAT_803db414);
          *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
          FUN_801ec1ac(param_1,iVar6);
          FUN_800226cc((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                       (double)*(float *)(iVar6 + 0x49c),iVar6 + 0xec,param_1 + 0x12,param_1 + 0x14,
                       param_1 + 0x16);
          FUN_8002b8f0(param_1);
        }
        else {
          iVar3 = FUN_801eaac0(param_1,iVar6);
          if (iVar3 != 0) {
            FUN_801ebd60(param_1,iVar6);
            FUN_801ec7a0(param_1,iVar6);
            if (*(float *)(iVar6 + 0x3e4) == FLOAT_803e5ae8) {
              *(undefined4 *)(iVar6 + 0x47c) = *(undefined4 *)(iVar6 + 0x464);
              *(undefined4 *)(iVar6 + 0x480) = *(undefined4 *)(iVar6 + 0x468);
              *(undefined4 *)(iVar6 + 0x484) = *(undefined4 *)(iVar6 + 0x46c);
            }
            else {
              FUN_80247778((double)*(float *)(iVar6 + 0x3e0),iVar6 + 0x464,iVar6 + 0x47c);
              FUN_80247778((double)*(float *)(iVar6 + 0x3e0),iVar6 + 0x494,iVar6 + 0x494);
              *(float *)(iVar6 + 0x3e4) = *(float *)(iVar6 + 0x3e4) - FLOAT_803db414;
              if (*(float *)(iVar6 + 0x3e4) <= FLOAT_803e5ae8) {
                iVar3 = FUN_800550bc();
                if (iVar3 != 0) {
                  FUN_800550c4((double)FLOAT_803e5ae8,0);
                }
                *(float *)(iVar6 + 0x3e4) = FLOAT_803e5ae8;
              }
            }
            local_c4 = FLOAT_803e5ae8;
            local_c0 = FLOAT_803e5ae8;
            local_bc = FLOAT_803e5ae8;
            local_c8 = FLOAT_803e5aec;
            local_d0 = -*(short *)(iVar6 + 0x40e);
            local_ce = -param_1[1];
            local_cc = -param_1[2];
            FUN_80021ba0(auStack120,&local_d0);
            FUN_800226cc((double)FLOAT_803e5ae8,
                         (double)(*(float *)(iVar6 + 0x4b0) * *(float *)(iVar6 + 0x544)),
                         (double)FLOAT_803e5ae8,auStack120,&local_f4,auStack260,auStack236);
            local_f4 = local_f4 * *(float *)(iVar6 + 0x540);
            local_f0 = FLOAT_803e5ae8;
            FUN_80247778((double)FLOAT_803db414,&local_f4,&local_f4);
            FUN_80247730(iVar6 + 0x494,&local_f4,iVar6 + 0x494);
            *(float *)(iVar6 + 0x498) =
                 *(float *)(iVar6 + 0x4b0) * FLOAT_803db414 + *(float *)(iVar6 + 0x498);
            dVar7 = (double)FUN_80292b44((double)*(float *)(iVar6 + 0x548),(double)FLOAT_803db414);
            *(float *)(iVar6 + 0x494) = (float)((double)*(float *)(iVar6 + 0x494) * dVar7);
            dVar7 = (double)FUN_80292b44((double)*(float *)(iVar6 + 0x54c),(double)FLOAT_803db414);
            *(float *)(iVar6 + 0x49c) = (float)((double)*(float *)(iVar6 + 0x49c) * dVar7);
            FUN_801ec1ac(param_1,iVar6);
            FUN_800226cc((double)*(float *)(iVar6 + 0x494),(double)*(float *)(iVar6 + 0x498),
                         (double)*(float *)(iVar6 + 0x49c),iVar6 + 0xec,param_1 + 0x12,
                         param_1 + 0x14,param_1 + 0x16);
            FUN_8002b8f0(param_1);
          }
        }
        FUN_801eb0d4(param_1,iVar6);
        iVar3 = (int)(FLOAT_803e5ba0 * -*(float *)(iVar6 + 0x430));
        local_10 = (longlong)iVar3;
        FUN_801ea240((double)*(float *)(iVar6 + 0x49c),param_1,iVar6,iVar3,iVar6 + 0x461,7);
        FUN_801eb634(param_1,iVar6);
        *param_1 = *(undefined2 *)(iVar6 + 0x40e);
      }
    }
  }
  else {
    *(byte *)(iVar6 + 0x428) = *(byte *)(iVar6 + 0x428) & 0xfb | 4;
  }
  return;
}

