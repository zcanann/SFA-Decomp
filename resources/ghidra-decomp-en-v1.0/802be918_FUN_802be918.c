// Function: FUN_802be918
// Entry: 802be918
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x802beccc) */
/* WARNING: Removing unreachable block (ram,0x802becd4) */

void FUN_802be918(void)

{
  float fVar1;
  int iVar2;
  char cVar5;
  undefined4 uVar3;
  int iVar4;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  float local_68;
  float local_64;
  float local_60;
  undefined2 local_5c [4];
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  longlong local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar2 = FUN_802860d8();
  iVar8 = *(int *)(iVar2 + 0xb8);
  FUN_8002b9ec();
  *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6e) = 0;
  *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6f) = 0;
  if ((*(int *)(iVar8 + 0xb54) == 0) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
    uVar3 = FUN_8002bdf4(0x18,0x6f5);
    uVar3 = FUN_8002df90(uVar3,4,(int)*(char *)(iVar2 + 0xac),0xffffffff,
                         *(undefined4 *)(iVar2 + 0x30));
    FUN_80037d2c(iVar2,uVar3,2);
    *(undefined4 *)(iVar8 + 0xb54) = uVar3;
  }
  *(undefined2 *)(iVar8 + 0x14de) = 5;
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) & 0xf7;
  if (*(char *)(iVar8 + 0x14e6) == '\x02') {
    FUN_8011f3ec(0x13);
    *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6a) = 0xf4;
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6b) = 0xf4;
    local_40 = (longlong)(int)FLOAT_803db414;
    FUN_802be6e8(iVar2,(int)FLOAT_803db414,0xffffffff);
  }
  else {
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6a) = 0;
    *(undefined *)(*(int *)(iVar2 + 0x54) + 0x6b) = 0;
    fVar1 = FLOAT_803e8304;
    *(float *)(iVar8 + 0x294) = FLOAT_803e8304;
    *(float *)(iVar8 + 0x284) = fVar1;
    *(float *)(iVar8 + 0x280) = fVar1;
    *(float *)(iVar2 + 0x24) = fVar1;
    *(float *)(iVar2 + 0x28) = fVar1;
    *(float *)(iVar2 + 0x2c) = fVar1;
    FUN_802be6e8(iVar2,DAT_803db410,0xffffffff);
  }
  FUN_8003b310(iVar2,iVar8 + 0x38c);
  FUN_80038f38(iVar2,iVar8 + 0x3bc);
  FUN_80115094(iVar2,iVar8 + 0x3ec);
  if ((*(byte *)(iVar2 + 0xaf) & 1) != 0) {
    *(byte *)(iVar8 + 0x14ec) = *(byte *)(iVar8 + 0x14ec) & 0xef | 0x10;
    iVar4 = (**(code **)(*DAT_803dca68 + 0x20))(0xc1);
    if (iVar4 == 0) {
      if ((*(char *)(iVar8 + 0x14f4) != -1) &&
         (iVar4 = (**(code **)(*DAT_803dca68 + 0x1c))(), iVar4 == 0)) {
        if ((*(byte *)(iVar8 + 0x14ec) >> 3 & 1) == 0) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar8 + 0x14f4),iVar2,0xffffffff);
          FUN_80014b3c(0,0x100);
        }
        else {
          *(byte *)(iVar8 + 0x14ec) = *(byte *)(iVar8 + 0x14ec) & 0xef | 0x10;
        }
      }
    }
    else {
      (**(code **)(*DAT_803dca54 + 0x48))(1,iVar2,0xffffffff);
      FUN_80014b3c(0,0x100);
      *(short *)(iVar8 + 0x14e2) = *(short *)(iVar8 + 0x14e2) + 4;
      iVar4 = FUN_8001ffb4(0xc1);
      FUN_800200e8(0xc1,iVar4 + -1);
    }
  }
  *(byte *)(iVar8 + 0x264) = *(byte *)(iVar8 + 0x264) | 0x10;
  dVar10 = (double)*(float *)(iVar2 + 0x28);
  *(float *)(iVar2 + 0x28) = FLOAT_803e8304;
  *(uint *)(iVar8 + 0x314) = *(uint *)(iVar8 + 0x314) & 0xfffffff8;
  fVar1 = FLOAT_803e8380;
  if (*(char *)(iVar8 + 0x13fe) == '\b') {
    fVar1 = FLOAT_803e837c;
  }
  FUN_8006edcc((double)*(float *)(iVar8 + 0x280),(double)fVar1,iVar2,*(undefined4 *)(iVar8 + 0x314),
               *(char *)(iVar8 + 0x13fe),iVar8 + 0xb18,iVar8 + 4);
  *(float *)(iVar2 + 0x28) = (float)dVar10;
  if ((*(ushort *)(iVar8 + 0x1430) & 8) != 0) {
    local_68 = FLOAT_803e833c * *(float *)(iVar2 + 0x24);
    local_64 = FLOAT_803e8304;
    local_60 = FLOAT_803e833c * *(float *)(iVar2 + 0x2c);
    iVar6 = 0;
    dVar10 = (double)FLOAT_803e835c;
    dVar11 = (double)FLOAT_803e8338;
    iVar4 = iVar8;
    do {
      local_50 = (float)(dVar10 * (double)*(float *)(iVar2 + 0x24) +
                        (double)*(float *)(iVar4 + 0xb18));
      local_4c = *(undefined4 *)(iVar4 + 0xb1c);
      local_48 = (float)(dVar10 * (double)*(float *)(iVar2 + 0x2c) +
                        (double)*(float *)(iVar4 + 0xb20));
      local_54 = (float)dVar11;
      local_5c[0] = 2;
      iVar7 = 2;
      do {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x7e6,local_5c,0x200001,0xffffffff,&local_68);
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      iVar4 = iVar4 + 0xc;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 4);
    *(ushort *)(iVar8 + 0x1430) = *(ushort *)(iVar8 + 0x1430) & 0xfff7;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_80286124();
  return;
}

