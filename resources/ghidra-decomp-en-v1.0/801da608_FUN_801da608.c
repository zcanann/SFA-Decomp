// Function: FUN_801da608
// Entry: 801da608
// Size: 700 bytes

/* WARNING: Removing unreachable block (ram,0x801da89c) */

void FUN_801da608(int param_1)

{
  int iVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  char *pcVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002b9ec();
  dVar8 = (double)FUN_8002166c(param_1 + 0x18,iVar1 + 0x18);
  if (*pcVar6 == '\0') {
    if ((iVar1 != 0) && (iVar2 = FUN_802966cc(iVar1), iVar2 != 0)) {
      iVar2 = FUN_8001ffb4(0x18b);
      if (iVar2 == 0) {
        FUN_80295cf4(iVar1,0);
        FUN_80030304((double)FLOAT_803e54d0,param_1);
        *(ushort *)(param_1 + 2) = (ushort)*(byte *)(iVar5 + 0x19) << 8;
        *(ushort *)(param_1 + 4) = (ushort)*(byte *)(iVar5 + 0x18) << 8;
        *(code **)(param_1 + 0xbc) = FUN_801da284;
        *pcVar6 = '\x01';
        cVar4 = FUN_8002e04c();
        if (cVar4 == '\0') {
          uVar3 = 0;
        }
        else {
          iVar1 = FUN_8002bdf4(0x20,0x659);
          *(undefined *)(iVar1 + 4) = 2;
          *(undefined *)(iVar1 + 7) = 0xff;
          uVar3 = FUN_8002b5a0(param_1);
        }
        *(undefined4 *)(pcVar6 + 0x38) = uVar3;
        *(float *)(pcVar6 + 0x70) = FLOAT_803e550c;
      }
      else {
        FUN_801da4a8(param_1,*(undefined4 *)(param_1 + 0xb8),0);
      }
    }
  }
  else if (*pcVar6 == '\x01') {
    iVar1 = FUN_80038024(param_1);
    if (iVar1 == 0) {
      if (dVar8 <= (double)FLOAT_803e5510) {
        if ((dVar8 < (double)FLOAT_803e5514) && (pcVar6[3] == '\0')) {
          pcVar6[3] = '\x01';
          FUN_80042f78(8);
        }
      }
      else if (pcVar6[3] != '\0') {
        pcVar6[3] = '\0';
        FUN_800437bc(0x13,0x20000000);
      }
    }
    else {
      uVar3 = FUN_80036e58(0xf,param_1,0);
      (**(code **)(*DAT_803dca54 + 0x48))(0,uVar3,0xffffffff);
      *pcVar6 = '\x02';
      *(float *)(pcVar6 + 4) = FLOAT_803e54e0;
      FUN_800200e8(0x18b,1);
    }
  }
  else if (pcVar6[3] != '\0') {
    pcVar6[3] = '\0';
    FUN_800437bc(0x13,0x20000000);
    FUN_800200e8(0x3b8,1);
  }
  FUN_8011f38c(0);
  *(float *)(pcVar6 + 0x6c) = FLOAT_803e54d8 * FLOAT_803db414 + *(float *)(pcVar6 + 0x6c);
  if (FLOAT_803e54d0 < *(float *)(pcVar6 + 0x6c)) {
    *(float *)(pcVar6 + 0x6c) = FLOAT_803e54d4;
  }
  *(float *)(pcVar6 + 0x70) = FLOAT_803e54d8 * FLOAT_803db414 + *(float *)(pcVar6 + 0x70);
  if ((FLOAT_803e54d0 < *(float *)(pcVar6 + 0x70)) &&
     (*(float *)(pcVar6 + 0x70) = FLOAT_803e54d4, *pcVar6 == '\x01')) {
    FUN_8000bb18(param_1,0x3fe);
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

