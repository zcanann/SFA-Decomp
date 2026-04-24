// Function: FUN_8014460c
// Entry: 8014460c
// Size: 1348 bytes

undefined4 FUN_8014460c(int param_1,char **param_2)

{
  bool bVar1;
  char cVar2;
  byte bVar4;
  uint uVar3;
  uint uVar5;
  int iVar6;
  char cVar7;
  short local_18 [4];
  
  bVar1 = false;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  uVar5 = FUN_8001ffb4(0xc1);
  uVar5 = uVar5 & 0xff;
  if (uVar5 != 0) {
    FUN_8011f3a8(local_18);
    bVar1 = local_18[0] == 0xc1;
    iVar6 = FUN_8012ebc8();
    if (iVar6 == 0xc1) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) == 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_8002b6d8(param_1,0,0,0,0,4);
    }
    else {
      iVar6 = (**(code **)(*DAT_803dca68 + 0x20))(0xc1);
      if (iVar6 != 0) {
        cVar7 = **param_2;
        cVar2 = (*param_2)[1];
        if (cVar7 == cVar2) {
          iVar6 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x4000;
          *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 1;
          if (FLOAT_803e23dc == *(float *)(iVar6 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e2410 == *(float *)(iVar6 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar6 + 0x2b4) - *(float *)(iVar6 + 0x2b0) <= FLOAT_803e2414) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
            *(float *)(iVar6 + 0x79c) = FLOAT_803e2440;
            *(float *)(iVar6 + 0x838) = FLOAT_803e23dc;
            FUN_80148bc8(s_in_water_8031d46c);
          }
          else {
            FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
            FUN_80148bc8(s_out_of_water_8031d478);
          }
          (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
          *(byte *)(iVar6 + 0x82e) = *(byte *)(iVar6 + 0x82e) & 0xdf | 0x20;
        }
        else {
          bVar4 = cVar2 - cVar7;
          uVar3 = (uint)(bVar4 >> 2);
          if ((bVar4 & 3) != 0) {
            uVar3 = uVar3 + 1;
          }
          if (uVar5 < uVar3) {
            *(char *)((int)param_2 + 0x82d) = cVar7 + (char)(uVar5 << 2);
            FUN_800200e8(0xc1,0);
          }
          else {
            *(char *)((int)param_2 + 0x82d) = cVar7 + (char)(uVar3 << 2);
            FUN_800200e8(0xc1,uVar5 - uVar3);
          }
          if ((byte)(*param_2)[1] < *(byte *)((int)param_2 + 0x82d)) {
            *(char *)((int)param_2 + 0x82d) = (*param_2)[1];
          }
          iVar6 = *(int *)(param_1 + 0xb8);
          *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x4000;
          if (FLOAT_803e23dc == *(float *)(iVar6 + 0x2ac)) {
            bVar1 = false;
          }
          else if (FLOAT_803e2410 == *(float *)(iVar6 + 0x2b0)) {
            bVar1 = true;
          }
          else if (*(float *)(iVar6 + 0x2b4) - *(float *)(iVar6 + 0x2b0) <= FLOAT_803e2414) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
            *(float *)(iVar6 + 0x79c) = FLOAT_803e2440;
            *(float *)(iVar6 + 0x838) = FLOAT_803e23dc;
            FUN_80148bc8(s_in_water_8031d46c);
          }
          else {
            FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
            FUN_80148bc8(s_out_of_water_8031d478);
          }
          (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
          *(byte *)(iVar6 + 0x82e) = *(byte *)(iVar6 + 0x82e) & 0xdf | 0x20;
          param_2[0x15] = (char *)((uint)param_2[0x15] | 0x40000000);
        }
        FUN_80014b3c(0,0x100);
        return 1;
      }
    }
  }
  else {
    cVar7 = FUN_8001ffb4(0x4e3);
    if ((cVar7 != -1) && (iVar6 = FUN_8012ebc8(), iVar6 == -1)) {
      if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
        FUN_800200e8(0x4e3,0xff);
        iVar6 = *(int *)(param_1 + 0xb8);
        *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 0x4000;
        if (cVar7 != '\x02') {
          *(uint *)(iVar6 + 0x54) = *(uint *)(iVar6 + 0x54) | 1;
        }
        if (FLOAT_803e23dc == *(float *)(iVar6 + 0x2ac)) {
          bVar1 = false;
        }
        else if (FLOAT_803e2410 == *(float *)(iVar6 + 0x2b0)) {
          bVar1 = true;
        }
        else if (*(float *)(iVar6 + 0x2b4) - *(float *)(iVar6 + 0x2b0) <= FLOAT_803e2414) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
          *(float *)(iVar6 + 0x79c) = FLOAT_803e2440;
          *(float *)(iVar6 + 0x838) = FLOAT_803e23dc;
          FUN_80148bc8(s_in_water_8031d46c);
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
          FUN_80148bc8(s_out_of_water_8031d478);
        }
        (**(code **)(*DAT_803dca54 + 0x48))(cVar7,param_1,0xffffffff);
        *(byte *)(iVar6 + 0x82e) = *(byte *)(iVar6 + 0x82e) & 0xdf | 0x20;
        FUN_80014b3c(0,0x100);
        return 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      FUN_8002b6d8(param_1,0,0,0,0,2);
    }
  }
  return 0;
}

