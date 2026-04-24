// Function: FUN_80144994
// Entry: 80144994
// Size: 1348 bytes

undefined4 FUN_80144994(int param_1,int *param_2)

{
  bool bVar1;
  char cVar2;
  char cVar3;
  byte bVar5;
  uint uVar4;
  uint uVar6;
  int iVar7;
  short local_18 [4];
  
  bVar1 = false;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  uVar6 = FUN_80020078(0xc1);
  uVar6 = uVar6 & 0xff;
  if (uVar6 != 0) {
    FUN_8011f68c(local_18);
    bVar1 = local_18[0] == 0xc1;
    iVar7 = FUN_8012f000();
    if (iVar7 == 0xc1) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_8002b7b0(param_1,0,0,0,'\0','\x04');
    }
    else {
      iVar7 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc1);
      if (iVar7 != 0) {
        cVar2 = *(char *)*param_2;
        cVar3 = ((char *)*param_2)[1];
        if (cVar2 == cVar3) {
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
          if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_8013a778((double)FLOAT_803e30cc,param_1,8,0);
            *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
            *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
            FUN_80148ff0();
          }
          else {
            FUN_8013a778((double)FLOAT_803e30d4,param_1,0,0);
            FUN_80148ff0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        }
        else {
          bVar5 = cVar3 - cVar2;
          uVar4 = (uint)(bVar5 >> 2);
          if ((bVar5 & 3) != 0) {
            uVar4 = uVar4 + 1;
          }
          if (uVar6 < uVar4) {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar6 << 2);
            FUN_800201ac(0xc1,0);
          }
          else {
            *(char *)((int)param_2 + 0x82d) = cVar2 + (char)(uVar4 << 2);
            FUN_800201ac(0xc1,uVar6 - uVar4);
          }
          if (*(byte *)(*param_2 + 1) < *(byte *)((int)param_2 + 0x82d)) {
            *(byte *)((int)param_2 + 0x82d) = *(byte *)(*param_2 + 1);
          }
          iVar7 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
          if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_8013a778((double)FLOAT_803e30cc,param_1,8,0);
            *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
            *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
            FUN_80148ff0();
          }
          else {
            FUN_8013a778((double)FLOAT_803e30d4,param_1,0,0);
            FUN_80148ff0();
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
          *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
          param_2[0x15] = param_2[0x15] | 0x40000000;
        }
        FUN_80014b68(0,0x100);
        return 1;
      }
    }
  }
  else {
    uVar6 = FUN_80020078(0x4e3);
    uVar6 = uVar6 & 0xff;
    if ((uVar6 != 0xff) && (iVar7 = FUN_8012f000(), iVar7 == -1)) {
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_800201ac(0x4e3,0xff);
        iVar7 = *(int *)(param_1 + 0xb8);
        *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 0x4000;
        if (uVar6 != 2) {
          *(uint *)(iVar7 + 0x54) = *(uint *)(iVar7 + 0x54) | 1;
        }
        if (FLOAT_803e306c == *(float *)(iVar7 + 0x2ac)) {
          bVar1 = false;
        }
        else if (FLOAT_803e30a0 == *(float *)(iVar7 + 0x2b0)) {
          bVar1 = true;
        }
        else if (*(float *)(iVar7 + 0x2b4) - *(float *)(iVar7 + 0x2b0) <= FLOAT_803e30a4) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          FUN_8013a778((double)FLOAT_803e30cc,param_1,8,0);
          *(float *)(iVar7 + 0x79c) = FLOAT_803e30d0;
          *(float *)(iVar7 + 0x838) = FLOAT_803e306c;
          FUN_80148ff0();
        }
        else {
          FUN_8013a778((double)FLOAT_803e30d4,param_1,0,0);
          FUN_80148ff0();
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(uVar6,param_1,0xffffffff);
        *(byte *)(iVar7 + 0x82e) = *(byte *)(iVar7 + 0x82e) & 0xdf | 0x20;
        FUN_80014b68(0,0x100);
        return 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_8002b7b0(param_1,0,0,0,'\0','\x02');
    }
  }
  return 0;
}

