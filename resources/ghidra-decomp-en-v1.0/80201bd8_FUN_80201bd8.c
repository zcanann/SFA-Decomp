// Function: FUN_80201bd8
// Entry: 80201bd8
// Size: 1240 bytes

/* WARNING: Removing unreachable block (ram,0x80202088) */
/* WARNING: Removing unreachable block (ram,0x80202090) */

void FUN_80201bd8(void)

{
  int iVar1;
  int iVar2;
  short sVar6;
  undefined4 *puVar3;
  undefined2 *puVar4;
  short sVar7;
  short *psVar5;
  int iVar8;
  bool bVar9;
  undefined4 uVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  undefined8 extraout_f1;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar14;
  undefined8 uVar15;
  float local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  int local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  double local_50;
  longlong local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar15 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  iVar8 = (int)uVar15;
  iVar12 = *(int *)(iVar1 + 0xb8);
  iVar11 = *(int *)(iVar12 + 0x40c);
  *(byte *)(iVar11 + 0x14) = *(byte *)(iVar11 + 0x14) | 2;
  *(byte *)(iVar11 + 0x15) = *(byte *)(iVar11 + 0x15) & 0xfb;
  uVar15 = extraout_f1;
  FUN_8000da58(iVar1,0x441);
  if (*(char *)(iVar8 + 0x27a) != '\0') {
    FUN_80035f20(iVar1);
  }
  FUN_80035dac(iVar1);
  *(float *)(iVar8 + 0x2a0) = FLOAT_803e62f4;
  if (*(int *)(iVar11 + 0x18) == 0) {
    sVar6 = *(short *)(iVar11 + 0x1c);
    if (sVar6 != -1) {
      local_58 = *(undefined4 *)(iVar11 + 0x30);
      local_5c = *(undefined4 *)(iVar11 + 0x2c);
      uVar10 = *(undefined4 *)(iVar11 + 0x24);
      local_60 = *(undefined4 *)(iVar11 + 0x28);
      iVar2 = FUN_800138c4(uVar10);
      if (iVar2 == 0) {
        FUN_80013958(uVar10,&local_60);
      }
      uVar10 = *(undefined4 *)(iVar11 + 0x24);
      local_6c = 9;
      local_68 = 0;
      local_64 = (int)sVar6;
      iVar2 = FUN_800138c4(uVar10);
      if (iVar2 == 0) {
        FUN_80013958(uVar10,&local_6c);
      }
      *(undefined *)(iVar11 + 0x34) = 1;
      *(undefined2 *)(iVar11 + 0x1c) = 0xffff;
    }
    if (*(char *)(iVar8 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,iVar1,0xf,0);
      *(undefined *)(iVar8 + 0x346) = 0;
    }
    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar12 + 0x406));
    dVar14 = (double)((float)(local_50 - DOUBLE_803e62e0) / FLOAT_803e62c4);
    iVar12 = FUN_8002208c((double)FLOAT_803e62c8,(double)FLOAT_803e632c,iVar11 + 0x4c);
    if (iVar12 != 0) {
      FUN_8000bb18(iVar1,0x43f);
    }
  }
  else {
    iVar2 = FUN_8002208c((double)FLOAT_803e62c8,(double)FLOAT_803e632c,iVar11 + 0x48);
    if (iVar2 != 0) {
      FUN_8000bb18(iVar1,0x440);
    }
    if (*(char *)(iVar8 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,iVar1,0x11,0);
      *(undefined *)(iVar8 + 0x346) = 0;
    }
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e6300;
    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar12 + 0x406));
    dVar14 = (double)((float)(local_50 - DOUBLE_803e62e0) / FLOAT_803e6324);
  }
  *(undefined *)(iVar8 + 0x34d) = 0x1f;
  iVar12 = FUN_80202da4((double)FLOAT_803e6330,dVar14,(double)FLOAT_803e62cc,uVar15,iVar1,
                        *(undefined4 *)(iVar8 + 0x2d0));
  if (iVar12 != 0) {
    *(undefined *)(iVar11 + 0x34) = 1;
  }
  if ((*(byte *)(iVar11 + 0x44) >> 5 & 1) == 0) {
    if (*(int *)(iVar11 + 0x18) == 0) {
      uVar10 = FUN_8002b9ec();
      sVar6 = FUN_800385e8(iVar1,uVar10,&local_88);
      bVar9 = false;
      iVar12 = (int)sVar6;
      if (iVar12 < 0) {
        iVar12 = -iVar12;
      }
      if ((iVar12 < 0x1c71) && (local_88 < FLOAT_803e62d0)) {
        bVar9 = true;
      }
      if (bVar9) {
        puVar3 = (undefined4 *)FUN_800394a0();
        iVar12 = 1;
        do {
          puVar3 = puVar3 + 1;
          puVar4 = (undefined2 *)FUN_800395d8(iVar1,*puVar3);
          if (puVar4 != (undefined2 *)0x0) {
            puVar4[2] = 0;
            *puVar4 = 0;
          }
          iVar12 = iVar12 + 1;
        } while (iVar12 < 9);
        uVar10 = FUN_8002b9ec();
        *(undefined4 *)(iVar8 + 0x2d0) = uVar10;
        local_70 = *(undefined4 *)(iVar11 + 0x30);
        local_74 = *(undefined4 *)(iVar11 + 0x2c);
        uVar10 = *(undefined4 *)(iVar11 + 0x24);
        local_78 = *(undefined4 *)(iVar11 + 0x28);
        iVar12 = FUN_800138c4(uVar10);
        if (iVar12 == 0) {
          FUN_80013958(uVar10,&local_78);
        }
        uVar10 = *(undefined4 *)(iVar11 + 0x24);
        local_84 = 2;
        local_80 = 0;
        local_7c = 0;
        iVar12 = FUN_800138c4(uVar10);
        if (iVar12 == 0) {
          FUN_80013958(uVar10,&local_84);
        }
        *(undefined *)(iVar11 + 0x34) = 1;
      }
    }
  }
  else {
    FUN_80202a2c(dVar14,iVar1,&DAT_803296fc,&DAT_8032970c,4);
  }
  if ((*(byte *)(iVar11 + 0x44) >> 6 & 1) == 0) {
    if (*(int *)(iVar11 + 0x18) == 0) {
      iVar11 = (int)-(FLOAT_803e6328 * *(float *)(iVar8 + 0x280));
      local_50 = (double)(longlong)iVar11;
      iVar12 = (int)-(FLOAT_803e6328 * *(float *)(iVar8 + 0x284));
      local_48 = (longlong)iVar12;
      sVar6 = (short)iVar11;
      if (sVar6 < -0x500) {
        sVar6 = -0x500;
      }
      else if (0x500 < sVar6) {
        sVar6 = 0x500;
      }
      sVar7 = (short)iVar12;
      if (sVar7 < -0x500) {
        sVar7 = -0x500;
      }
      else if (0x500 < sVar7) {
        sVar7 = 0x500;
      }
      puVar3 = (undefined4 *)FUN_800394a0();
      iVar11 = 1;
      do {
        puVar3 = puVar3 + 1;
        psVar5 = (short *)FUN_800395d8(iVar1,*puVar3);
        if (psVar5 != (short *)0x0) {
          psVar5[2] = sVar7;
          *psVar5 = sVar6;
        }
        iVar11 = iVar11 + 1;
      } while (iVar11 < 9);
    }
  }
  else {
    puVar3 = (undefined4 *)FUN_800394a0();
    iVar11 = 1;
    do {
      puVar3 = puVar3 + 1;
      puVar4 = (undefined2 *)FUN_800395d8(iVar1,*puVar3);
      if (puVar4 != (undefined2 *)0x0) {
        puVar4[2] = 0;
        *puVar4 = 0;
      }
      iVar11 = iVar11 + 1;
    } while (iVar11 < 9);
  }
  FUN_8002f5d4((double)*(float *)(iVar8 + 0x280),iVar1,iVar8 + 0x2a0);
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  FUN_80286124(0);
  return;
}

