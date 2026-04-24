// Function: FUN_802017a4
// Entry: 802017a4
// Size: 1076 bytes

/* WARNING: Removing unreachable block (ram,0x80201bb0) */
/* WARNING: Removing unreachable block (ram,0x80201bb8) */

void FUN_802017a4(void)

{
  int iVar1;
  short sVar5;
  undefined4 *puVar2;
  undefined2 *puVar3;
  short sVar6;
  short *psVar4;
  int iVar7;
  bool bVar8;
  int iVar9;
  undefined4 uVar10;
  int iVar11;
  undefined4 uVar12;
  undefined8 extraout_f1;
  undefined8 in_f30;
  double in_f31;
  undefined8 uVar13;
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
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar13 >> 0x20);
  iVar7 = (int)uVar13;
  iVar9 = *(int *)(iVar1 + 0xb8);
  iVar11 = *(int *)(iVar9 + 0x40c);
  *(byte *)(iVar11 + 0x14) = *(byte *)(iVar11 + 0x14) | 2;
  *(byte *)(iVar11 + 0x15) = *(byte *)(iVar11 + 0x15) & 0xfb;
  uVar13 = extraout_f1;
  if (*(char *)(iVar7 + 0x27a) != '\0') {
    FUN_80035f20();
    FUN_80035dac(iVar1);
  }
  *(float *)(iVar7 + 0x2a0) = FLOAT_803e62f4;
  if (*(int *)(iVar11 + 0x18) == 0) {
    sVar5 = *(short *)(iVar11 + 0x1c);
    if (sVar5 != -1) {
      local_58 = *(undefined4 *)(iVar11 + 0x30);
      local_5c = *(undefined4 *)(iVar11 + 0x2c);
      uVar10 = *(undefined4 *)(iVar11 + 0x24);
      local_60 = *(undefined4 *)(iVar11 + 0x28);
      iVar9 = FUN_800138c4(uVar10);
      if (iVar9 == 0) {
        FUN_80013958(uVar10,&local_60);
      }
      uVar10 = *(undefined4 *)(iVar11 + 0x24);
      local_6c = 9;
      local_68 = 0;
      local_64 = (int)sVar5;
      iVar9 = FUN_800138c4(uVar10);
      if (iVar9 == 0) {
        FUN_80013958(uVar10,&local_6c);
      }
      *(undefined *)(iVar11 + 0x34) = 1;
      *(undefined2 *)(iVar11 + 0x1c) = 0xffff;
    }
  }
  else {
    if (*(char *)(iVar7 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e62a8,iVar1,0x11,0);
      *(undefined *)(iVar7 + 0x346) = 0;
    }
    *(float *)(iVar7 + 0x2a0) = FLOAT_803e6300;
    local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar9 + 0x406));
    in_f31 = (double)((float)(local_50 - DOUBLE_803e62e0) / FLOAT_803e6324);
  }
  *(undefined *)(iVar7 + 0x34d) = 0x1f;
  iVar9 = FUN_80202c78((double)FLOAT_803e62b4,in_f31,(double)FLOAT_803e62cc,uVar13,iVar1,
                       *(undefined4 *)(iVar7 + 0x2d0));
  if (iVar9 != 0) {
    *(undefined *)(iVar11 + 0x34) = 1;
  }
  if ((*(byte *)(iVar11 + 0x44) >> 5 & 1) == 0) {
    if (*(int *)(iVar11 + 0x18) == 0) {
      uVar10 = FUN_8002b9ec();
      sVar5 = FUN_800385e8(iVar1,uVar10,&local_88);
      bVar8 = false;
      iVar9 = (int)sVar5;
      if (iVar9 < 0) {
        iVar9 = -iVar9;
      }
      if ((iVar9 < 0x1c71) && (local_88 < FLOAT_803e62d0)) {
        bVar8 = true;
      }
      if (bVar8) {
        puVar2 = (undefined4 *)FUN_800394a0();
        iVar9 = 1;
        do {
          puVar2 = puVar2 + 1;
          puVar3 = (undefined2 *)FUN_800395d8(iVar1,*puVar2);
          if (puVar3 != (undefined2 *)0x0) {
            puVar3[2] = 0;
            *puVar3 = 0;
          }
          iVar9 = iVar9 + 1;
        } while (iVar9 < 9);
        uVar10 = FUN_8002b9ec();
        *(undefined4 *)(iVar7 + 0x2d0) = uVar10;
        local_70 = *(undefined4 *)(iVar11 + 0x30);
        local_74 = *(undefined4 *)(iVar11 + 0x2c);
        uVar10 = *(undefined4 *)(iVar11 + 0x24);
        local_78 = *(undefined4 *)(iVar11 + 0x28);
        iVar9 = FUN_800138c4(uVar10);
        if (iVar9 == 0) {
          FUN_80013958(uVar10,&local_78);
        }
        uVar10 = *(undefined4 *)(iVar11 + 0x24);
        local_84 = 2;
        local_80 = 0;
        local_7c = 0;
        iVar9 = FUN_800138c4(uVar10);
        if (iVar9 == 0) {
          FUN_80013958(uVar10,&local_84);
        }
        *(undefined *)(iVar11 + 0x34) = 1;
      }
    }
  }
  else {
    FUN_80202a2c(in_f31,iVar1,&DAT_803296fc,&DAT_8032970c,4);
  }
  if ((*(byte *)(iVar11 + 0x44) >> 6 & 1) == 0) {
    if (*(int *)(iVar11 + 0x18) == 0) {
      iVar9 = (int)-(FLOAT_803e6328 * *(float *)(iVar7 + 0x280));
      local_50 = (double)(longlong)iVar9;
      iVar11 = (int)-(FLOAT_803e6328 * *(float *)(iVar7 + 0x284));
      local_48 = (longlong)iVar11;
      sVar5 = (short)iVar9;
      if (sVar5 < -0x500) {
        sVar5 = -0x500;
      }
      else if (0x500 < sVar5) {
        sVar5 = 0x500;
      }
      sVar6 = (short)iVar11;
      if (sVar6 < -0x500) {
        sVar6 = -0x500;
      }
      else if (0x500 < sVar6) {
        sVar6 = 0x500;
      }
      puVar2 = (undefined4 *)FUN_800394a0();
      iVar9 = 1;
      do {
        puVar2 = puVar2 + 1;
        psVar4 = (short *)FUN_800395d8(iVar1,*puVar2);
        if (psVar4 != (short *)0x0) {
          psVar4[2] = sVar6;
          *psVar4 = sVar5;
        }
        iVar9 = iVar9 + 1;
      } while (iVar9 < 9);
    }
  }
  else {
    puVar2 = (undefined4 *)FUN_800394a0();
    iVar9 = 1;
    do {
      puVar2 = puVar2 + 1;
      puVar3 = (undefined2 *)FUN_800395d8(iVar1,*puVar2);
      if (puVar3 != (undefined2 *)0x0) {
        puVar3[2] = 0;
        *puVar3 = 0;
      }
      iVar9 = iVar9 + 1;
    } while (iVar9 < 9);
  }
  FUN_8002f5d4((double)*(float *)(iVar7 + 0x280),iVar1,iVar7 + 0x2a0);
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  FUN_80286124(0);
  return;
}

