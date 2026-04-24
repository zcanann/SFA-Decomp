// Function: FUN_801bbb44
// Entry: 801bbb44
// Size: 1940 bytes

/* WARNING: Removing unreachable block (ram,0x801bc2b0) */
/* WARNING: Removing unreachable block (ram,0x801bc2a8) */
/* WARNING: Removing unreachable block (ram,0x801bc2b8) */

void FUN_801bbb44(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined8 uVar9;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar9 = FUN_802860dc();
  uVar1 = (undefined4)((ulonglong)uVar9 >> 0x20);
  iVar3 = (int)uVar9;
  iVar4 = *(int *)(iVar3 + 0x40c);
  if ((*(int *)(iVar4 + 0xb0) == 0) ||
     (*(int *)(iVar4 + 0xb0) = *(int *)(iVar4 + 0xb0) + -1, 0 < *(int *)(iVar4 + 0xb0))) {
    if (*(char *)(iVar4 + 0xb6) < '\0') {
      FUN_80008cbc(0,0,0xdb,0);
      FUN_80008cbc(0,0,0xdc,0);
      FUN_80089710(7,1,0);
      FUN_800894a8((double)FLOAT_803e4c4c,(double)FLOAT_803e4c50,(double)FLOAT_803e4c54,7);
      FUN_800895e0(7,0xa0,0xa0,0xff,0x7f,0x28);
      *(byte *)(iVar4 + 0xb6) = *(byte *)(iVar4 + 0xb6) & 0x7f;
    }
    if ((*(uint *)(iVar3 + 0x314) & 4) != 0) {
      *(uint *)(iVar3 + 0x314) = *(uint *)(iVar3 + 0x314) & 0xfffffffb;
      FUN_8000bb18(uVar1,DAT_80325ab8 & 0xffff);
      DAT_803ddb80 = DAT_803ddb80 | 0x204;
      FUN_80014aa0((double)FLOAT_803e4bf8);
    }
    if ((*(uint *)(iVar3 + 0x314) & 2) != 0) {
      *(uint *)(iVar3 + 0x314) = *(uint *)(iVar3 + 0x314) & 0xfffffffd;
      FUN_8000bb18(uVar1,DAT_80325abc & 0xffff);
      DAT_803ddb80 = DAT_803ddb80 | 0x404;
      FUN_80014aa0((double)FLOAT_803e4bf8);
    }
    if ((*(uint *)(iVar3 + 0x314) & 0x10) != 0) {
      *(uint *)(iVar3 + 0x314) = *(uint *)(iVar3 + 0x314) & 0xffffffef;
      FUN_8000bb18(uVar1,DAT_80325ac0 & 0xffff);
      DAT_803ddb80 = DAT_803ddb80 | 0x804;
      FUN_80014aa0((double)FLOAT_803e4bf8);
    }
    if ((*(uint *)(iVar3 + 0x314) & 8) != 0) {
      *(uint *)(iVar3 + 0x314) = *(uint *)(iVar3 + 0x314) & 0xfffffff7;
      FUN_8000bb18(uVar1,DAT_80325ac4 & 0xffff);
      DAT_803ddb80 = DAT_803ddb80 | 0x1004;
      FUN_80014aa0((double)FLOAT_803e4bf8);
    }
    if ((DAT_803ddb80 & 0x2000) != 0) {
      iVar2 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b1,iVar4 + 0x4c,0x200001,0xffffffff,0);
        iVar2 = iVar2 + 1;
      } while (iVar2 < 0x32);
      (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b2,iVar4 + 0x4c,0x200001,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b3,iVar4 + 0x4c,0x200001,0xffffffff,0);
    }
    if ((DAT_803ddb80 & 0x80000) != 0) {
      (**(code **)(*DAT_803dcab4 + 0xc))(uVar1,0x800,0,1,0);
    }
    if (((DAT_803ddb80 & 0x8020) != 0) || (*(char *)(iVar3 + 0x354) < '\x02')) {
      if ((DAT_803ddb80 & 0x20) == 0) {
        iVar2 = FUN_800221a0(0,(int)*(char *)(iVar3 + 0x354));
        if ((iVar2 == 0) && (*(short *)(iVar3 + 0x402) == 2)) {
          (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b4,iVar4 + 0x34,0x200001,0xffffffff,0);
        }
      }
      else {
        iVar3 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b4,iVar4 + 0x34,0x200001,0xffffffff,0);
          iVar3 = iVar3 + 1;
        } while (iVar3 < 7);
      }
      if ((DAT_803ddb80 & 0x8000) != 0) {
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b2,iVar4 + 0x34,0x200001,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b3,iVar4 + 0x34,0x200001,0xffffffff,0);
      }
    }
    if ((DAT_803ddb80 & 0x101c0) != 0) {
      if ((DAT_803ddb80 & 0x40) != 0) {
        iVar3 = 0;
        dVar7 = (double)FLOAT_803e4c58;
        dVar8 = (double)FLOAT_803e4c5c;
        dVar6 = DOUBLE_803e4be0;
        do {
          uStack100 = FUN_800221a0(0xfffffffb,5);
          uStack100 = uStack100 ^ 0x80000000;
          local_68 = 0x43300000;
          local_78 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack100) - dVar6)
                            );
          uStack92 = FUN_800221a0(0xfffffffb,5);
          uStack92 = uStack92 ^ 0x80000000;
          local_60 = 0x43300000;
          local_74 = (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uStack92) - dVar6))
          ;
          uStack84 = FUN_800221a0(2,8);
          uStack84 = uStack84 ^ 0x80000000;
          local_58 = 0x43300000;
          local_70 = (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack84) - dVar6))
          ;
          FUN_80247494(iVar4 + 100,&local_78,&local_78);
          (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b5,iVar4 + 0x1c,0x200001,0xffffffff,&local_78);
          iVar3 = iVar3 + 1;
        } while (iVar3 < 5);
      }
      if ((DAT_803ddb80 & 0x80) != 0) {
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b5,iVar4 + 4,0x200001,0xffffffff,0);
      }
      if ((DAT_803ddb80 & 0x100) != 0) {
        local_78 = FLOAT_803e4c58;
        local_74 = FLOAT_803e4c60;
        uStack84 = FUN_800221a0(4,8);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_70 = FLOAT_803e4c64 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e4be0)
        ;
        FUN_80247494(iVar4 + 100,&local_78,&local_78);
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b6,iVar4 + 4,0x200001,0xffffffff,&local_78);
      }
      if ((DAT_803ddb80 & 0x10000) != 0) {
        local_78 = FLOAT_803e4bd8;
        local_74 = FLOAT_803e4c60;
        local_70 = FLOAT_803e4c68;
        FUN_80247494(iVar4 + 100,&local_78,&local_78);
        FUN_80003494(iVar4 + 0x94,&local_78,0xc);
        DAT_803ddb80 = DAT_803ddb80 | 0x20000;
      }
    }
    if ((DAT_803ddb80 & 0x4000) != 0) {
      iVar3 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(uVar1,0x4b7,0,1,0xffffffff,0);
        iVar3 = iVar3 + 1;
      } while (iVar3 < 0x32);
    }
    if ((DAT_803ddb80 & 1) != 0) {
      FUN_8000fad8();
      FUN_80014aa0((double)FLOAT_803e4bf8);
      FUN_8000e650((double)FLOAT_803e4bc4,(double)FLOAT_803e4bc8,(double)FLOAT_803e4bcc);
    }
    if ((DAT_803ddb80 & 0x40000) != 0) {
      FUN_8000fad8();
      FUN_80014aa0((double)FLOAT_803e4c6c);
      FUN_8000e650((double)FLOAT_803e4bc8,(double)FLOAT_803e4bf4,(double)FLOAT_803e4bf8);
    }
    if ((DAT_803ddb80 & 2) != 0) {
      FUN_8000fad8();
      dVar6 = (double)FLOAT_803e4bd8;
      FUN_8000e650(dVar6,dVar6,dVar6);
      FUN_8000e67c((double)FLOAT_803e4bd8);
    }
    if ((DAT_803ddb80 & 4) == 0) {
      FUN_800200e8(0x25e,0);
    }
    else {
      FUN_800200e8(0x25e,1);
    }
    DAT_803ddb80 = DAT_803ddb80 & 0xa1ff0;
  }
  else {
    *(undefined4 *)(iVar4 + 0xb0) = 0;
    FUN_8012dd7c(0);
    FUN_800552e8(0x77,1);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  FUN_80286128();
  return;
}

