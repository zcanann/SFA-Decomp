// Function: FUN_801698e8
// Entry: 801698e8
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x80169c9c) */
/* WARNING: Removing unreachable block (ram,0x80169c94) */
/* WARNING: Removing unreachable block (ram,0x80169ca4) */

void FUN_801698e8(short *param_1)

{
  int iVar1;
  short sVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined8 uVar5;
  undefined8 in_f29;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  double local_48;
  double local_40;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  piVar3 = *(int **)(param_1 + 0x5c);
  local_48 = (double)CONCAT44(0x43300000,*(uint *)(param_1 + 0x7a) ^ 0x80000000);
  *(int *)(param_1 + 0x7a) = (int)((float)(local_48 - DOUBLE_803e30e8) - FLOAT_803db414);
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_8000b7bc(param_1,0x7f);
    FUN_8002cbc4(param_1);
  }
  else if (*(char *)(param_1 + 0x1b) != '\0') {
    if (*(int *)(param_1 + 0x7a) < 0x11b) {
      *(float *)(param_1 + 0x14) = -(FLOAT_803e30f0 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
      if ((float)(local_40 - DOUBLE_803e3100) - FLOAT_803e30f4 * FLOAT_803db414 <= FLOAT_803e30f8) {
        FUN_8000b7bc(param_1,0x7f);
        *(undefined *)(param_1 + 0x1b) = 0;
      }
      else {
        local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1b));
        *(char *)(param_1 + 0x1b) =
             (char)(int)((float)(local_40 - DOUBLE_803e3100) - FLOAT_803e30f4 * FLOAT_803db414);
      }
      FUN_8000b888((double)FLOAT_803e30fc,param_1,0x40,(int)(uint)*(byte *)(param_1 + 0x1b) >> 1);
    }
    dVar8 = (double)(*(float *)(param_1 + 0x12) * FLOAT_803db414);
    dVar7 = (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414);
    dVar6 = (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414);
    FUN_8002b95c(dVar8,dVar7,dVar6,param_1);
    if (param_1[0x23] == 0x869) {
      FUN_80035df4(param_1,0x1f,1,0);
      *param_1 = *param_1 + 0x100;
      param_1[1] = param_1[1] + 0x800;
    }
    else {
      FUN_80035df4(param_1,10,1,0);
      sVar2 = FUN_800217c0(dVar8,dVar6);
      *param_1 = sVar2 + -0x8000;
      uVar5 = FUN_802931a0((double)(float)(dVar8 * dVar8 + (double)(float)(dVar6 * dVar6)));
      sVar2 = FUN_800217c0(uVar5,dVar7);
      param_1[1] = 0x4000 - sVar2;
    }
    FUN_80035f20(param_1);
    if (*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) {
      if (*(int *)(param_1 + 0x7a) < 0x17c) {
        FUN_801696d4(param_1);
        goto LAB_80169c94;
      }
      iVar1 = FUN_8002b9ec();
      if ((*(int *)(*(int *)(param_1 + 0x2a) + 0x50) == iVar1) ||
         (iVar1 = FUN_8002b9ac(), *(int *)(*(int *)(param_1 + 0x2a) + 0x50) == iVar1)) {
        FUN_801696d4(param_1);
        goto LAB_80169c94;
      }
    }
    if (*(char *)(*(int *)(param_1 + 0x2a) + 0xad) == '\0') {
      if (param_1[0x23] == 0x869) {
        FUN_80098b18((double)FLOAT_803e30e0,param_1,1,0,0,0);
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x714,0,2,0xffffffff,param_1 + 0x1b);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x715,0,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x715,0,1,0xffffffff,0);
      }
      iVar1 = *piVar3;
      if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0'))
      {
        sVar2 = FUN_800221a0(0xffffffe7,0x19);
        iVar1 = *piVar3;
        sVar2 = (ushort)*(byte *)(iVar1 + 0x2f9) + *(char *)(iVar1 + 0x2fa) + sVar2;
        if (sVar2 < 0) {
          sVar2 = 0;
          *(undefined *)(iVar1 + 0x2fa) = 0;
        }
        else if (0xff < sVar2) {
          sVar2 = 0xff;
          *(undefined *)(iVar1 + 0x2fa) = 0;
        }
        *(char *)(*piVar3 + 0x2f9) = (char)sVar2;
      }
    }
    else {
      FUN_801696d4(param_1);
    }
  }
LAB_80169c94:
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

