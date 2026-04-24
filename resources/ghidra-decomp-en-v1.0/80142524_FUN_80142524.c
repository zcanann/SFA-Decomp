// Function: FUN_80142524
// Entry: 80142524
// Size: 1264 bytes

void FUN_80142524(undefined2 *param_1,int param_2)

{
  short sVar1;
  bool bVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined2 *puVar7;
  
  puVar7 = (undefined2 *)0x0;
  if ((*(uint *)(param_2 + 0x54) & 0x10) == 0) {
    if (*(char *)(param_2 + 2000) != '\0') {
      if (*(char *)(param_2 + 2000) == '\x01') {
        iVar6 = *(int *)(param_2 + 0x7d4);
        iVar5 = *(int *)(param_1 + 0x5c);
        if ((param_1[0x58] & 0x1000) == 0) {
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
        iVar5 = FUN_8014460c(param_1,param_2);
        if ((iVar5 == 0) &&
           (iVar5 = FUN_8013b368((double)FLOAT_803e2488,param_1,param_2), iVar5 == 0)) {
          *(float *)(param_2 + 0x740) = *(float *)(param_2 + 0x740) - FLOAT_803db414;
          if (*(float *)(param_2 + 0x740) <= FLOAT_803e23dc) {
            uVar4 = FUN_800221a0(500,0x2ee);
            *(float *)(param_2 + 0x740) =
                 (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2460);
            iVar5 = *(int *)(param_1 + 0x5c);
            if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
               (((0x2f < (short)param_1[0x50] || ((short)param_1[0x50] < 0x29)) &&
                (iVar6 = FUN_8000b578(param_1,0x10), iVar6 == 0)))) {
              FUN_800393f8(param_1,iVar5 + 0x3a8,0x360,0x500,0xffffffff,0);
            }
          }
          if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
            bVar2 = false;
          }
          else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
            bVar2 = true;
          }
          else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
            bVar2 = false;
          }
          else {
            bVar2 = true;
          }
          if (bVar2) {
            FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
            *(float *)(param_2 + 0x79c) = FLOAT_803e2440;
            *(float *)(param_2 + 0x838) = FLOAT_803e23dc;
            FUN_80148bc8(s_in_water_8031d46c);
          }
          else {
            sVar1 = param_1[0x50];
            if (sVar1 != 0x31) {
              if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
                if ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0) {
                  FUN_8013a3f0((double)FLOAT_803e243c,param_1,0x31,0);
                }
              }
              else {
                FUN_8013a3f0((double)FLOAT_803e2444,param_1,0xd,0);
              }
            }
            FUN_80148bc8(s_out_of_water_8031d478);
          }
        }
      }
      *(undefined *)(param_2 + 2000) = 0;
      return;
    }
    puVar7 = (undefined2 *)FUN_80144e40();
  }
  if (puVar7 == (undefined2 *)0x0) {
    *(float *)(param_2 + 0x71c) = *(float *)(param_2 + 0x71c) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x71c) < FLOAT_803e23dc) {
      *(float *)(param_2 + 0x71c) = FLOAT_803e23dc;
    }
    FUN_80144b50(param_1,param_2);
    iVar5 = (*(code *)(&PTR_FUN_8031d354)[*(byte *)(param_2 + 10)])(param_1,param_2);
    if (iVar5 == 0) {
      if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
        bVar2 = false;
      }
      else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
        bVar2 = true;
      }
      else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
        *(float *)(param_2 + 0x79c) = FLOAT_803e2440;
        *(float *)(param_2 + 0x838) = FLOAT_803e23dc;
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2518,param_1,0x25,0);
      }
    }
  }
  else {
    *(undefined *)(param_2 + 0x374) = 2;
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,param_2 + 0xf8);
    *(undefined *)(param_2 + 8) = 1;
    *(undefined *)(param_2 + 10) = 0;
    fVar3 = FLOAT_803e23dc;
    *(float *)(param_2 + 0x71c) = FLOAT_803e23dc;
    *(float *)(param_2 + 0x720) = fVar3;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffffef;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffeffff;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffdffff;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xfffbffff;
    *(undefined *)(param_2 + 0xd) = 0xff;
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(puVar7 + 6);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(puVar7 + 8);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(puVar7 + 10);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(puVar7 + 0xc);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(puVar7 + 0xe);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(puVar7 + 0x10);
    FUN_80035f8c(param_1);
    *param_1 = *puVar7;
    *(undefined *)(param_2 + 9) = 0;
    fVar3 = FLOAT_803e23dc;
    *(float *)(param_2 + 0x10) = FLOAT_803e23dc;
    *(float *)(param_2 + 0x14) = fVar3;
    *(undefined4 *)(param_2 + 0xe0) = *(undefined4 *)(puVar7 + 0xc);
    *(undefined4 *)(param_2 + 0xe4) = *(undefined4 *)(puVar7 + 0xe);
    *(undefined4 *)(param_2 + 0xe8) = *(undefined4 *)(puVar7 + 0x10);
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) | 0x80000;
    *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffdfff;
  }
  return;
}

