// Function: FUN_801bf99c
// Entry: 801bf99c
// Size: 716 bytes

/* WARNING: Removing unreachable block (ram,0x801bfc44) */
/* WARNING: Removing unreachable block (ram,0x801bfc3c) */
/* WARNING: Removing unreachable block (ram,0x801bf9b4) */
/* WARNING: Removing unreachable block (ram,0x801bf9ac) */

void FUN_801bf99c(ushort *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  uint local_68;
  uint uStack_64;
  uint uStack_60;
  undefined auStack_5c [8];
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  if ((*(int *)(param_1 + 0x7a) == 0) &&
     ((*(int *)(param_1 + 0x18) != 0 ||
      (iVar1 = FUN_8005b478((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8)),
      -1 < iVar1)))) {
    local_68 = 0;
    do {
      iVar1 = FUN_800375e4((int)param_1,&uStack_64,&uStack_60,&local_68);
    } while (iVar1 != 0);
    pfVar4 = *(float **)(iVar5 + 0x40c);
    if ((*pfVar4 < FLOAT_803e5968) && (pfVar4[4] < FLOAT_803e596c)) {
      dVar8 = (double)(pfVar4[3] - *(float *)(param_1 + 8));
      if (dVar8 < (double)FLOAT_803e5970) {
        dVar8 = -dVar8;
      }
      if ((dVar8 < (double)FLOAT_803e5974) &&
         (local_4c = pfVar4[3], uVar2 = FUN_80022264(0x1e,0x3c),
         (int)uVar2 < (int)(uint)*(ushort *)((int)pfVar4 + 0x16))) {
        dVar7 = (double)(FLOAT_803e5978 * pfVar4[4]);
        uStack_3c = (int)(short)*param_1 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar6 = (double)FUN_802945e0();
        local_50 = -(float)(dVar7 * dVar6 - (double)*(float *)(param_1 + 6));
        uStack_34 = (int)(short)*param_1 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar6 = (double)FUN_80294964();
        local_48 = -(float)(dVar7 * dVar6 - (double)*(float *)(param_1 + 10));
        local_54 = FLOAT_803e5984 * (FLOAT_803e5988 - (float)(dVar8 / (double)FLOAT_803e5974));
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x32b,auStack_5c,1,0xffffffff,0);
        *(undefined2 *)((int)pfVar4 + 0x16) = 0;
      }
    }
    *(ushort *)((int)pfVar4 + 0x16) = *(short *)((int)pfVar4 + 0x16) + (ushort)DAT_803dc070;
    FUN_801bf454((int)param_1,iVar5);
    FUN_801bf5fc(param_1,iVar5);
    FUN_8002fb40((double)FLOAT_803e59b8,(double)FLOAT_803dc074);
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6e) = 9;
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x6f) = 1;
    FUN_80033a34(param_1);
    iVar1 = *(int *)(iVar5 + 0x40c);
    iVar5 = *(int *)(iVar1 + 0x18);
    if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
      uVar2 = (uint)*(byte *)(iVar5 + 0x2f9) + (int)*(char *)(iVar5 + 0x2fa) & 0xffff;
      if (0xc < uVar2) {
        uVar3 = FUN_80022264(0xfffffff4,0xc);
        uVar2 = uVar2 + uVar3 & 0xffff;
        if (0xff < uVar2) {
          uVar2 = 0xff;
          *(undefined *)(*(int *)(iVar1 + 0x18) + 0x2fa) = 0;
        }
      }
      *(char *)(*(int *)(iVar1 + 0x18) + 0x2f9) = (char)uVar2;
    }
  }
  return;
}

