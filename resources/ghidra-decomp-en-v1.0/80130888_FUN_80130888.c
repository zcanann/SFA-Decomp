// Function: FUN_80130888
// Entry: 80130888
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x80130cd0) */

void FUN_80130888(void)

{
  char cVar1;
  ushort uVar2;
  uint uVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860cc();
  puVar8 = &DAT_803a9458;
  for (iVar7 = 0; iVar7 < DAT_803dd911; iVar7 = iVar7 + 1) {
    if ((puVar8[0xb] & 0x4000) == 0) {
      if ((puVar8[0xb] & 0x1040) == 0) {
        puVar4 = puVar8;
        if (*(char *)(puVar8 + 0xf) != -1) {
          puVar4 = &DAT_803a9458 + *(char *)(puVar8 + 0xf) * 0x1e;
        }
        if ((puVar4[0xb] & 4) != 0) {
          iVar6 = 0;
          uVar5 = (uint)(short)puVar4[5];
          uVar2 = puVar4[6];
          dVar10 = DOUBLE_803e21e0;
          while( true ) {
            cVar1 = *(char *)((int)puVar4 + iVar6 + 0x1f);
            if ((cVar1 == -1) || (0x18 < iVar6)) break;
            FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - dVar10),
                         (double)(float)((double)CONCAT44(0x43300000,(int)(short)uVar2 ^ 0x80000000)
                                        - dVar10),(&DAT_8031c1b4)[cVar1 * 2],0xff,0x100);
            uVar5 = uVar5 + (byte)(&DAT_8031c1ba)[*(char *)((int)puVar4 + iVar6 + 0x1f) * 8];
            iVar6 = iVar6 + 1;
          }
        }
        if ((puVar4[0xb] & 0x800) == 0) {
          uVar5 = (uint)DAT_803dd90c;
        }
        else {
          uVar5 = DAT_803dd90c * 200 >> 8;
        }
        FUN_800173e4(puVar4[1]);
        uVar3 = uVar5;
        if (DAT_803dd912 != iVar7) {
          uVar3 = (int)uVar5 / 2;
        }
        iVar6 = FUN_800173c8(puVar4[1]);
        *(char *)(iVar6 + 0x1e) = (char)uVar3;
        if ((puVar4[0xb] & 0x100) != 0) {
          FUN_80019908(0,0,0,(DAT_803dd90e + 1) * (int)DAT_803dd90c >> 8 & 0xff);
          FUN_80016810(*puVar4,2,2);
        }
        if ((puVar4[0xb] & 0x80) == 0) {
          FUN_80019908(0xff,0xff,0xff,uVar5 & 0xff);
        }
        else if (DAT_803dd912 == iVar7) {
          iVar6 = (int)DAT_803dd90e;
          if ((puVar4[0xb] & 0x800) == 0) {
            uVar5 = (int)DAT_803dd90c << 8 | (uint)(int)DAT_803dd90c >> 0x18;
          }
          else {
            uVar5 = DAT_803dd90c * 200;
          }
          FUN_80019908(DAT_803dd904 +
                       (short)((uint)(iVar6 * ((int)DAT_803dd8fe - (int)(short)DAT_803dd904)) >> 8)
                       & 0xff,DAT_803dd902 +
                              (short)((uint)(iVar6 * ((int)DAT_803dd8fc - (int)(short)DAT_803dd902))
                                     >> 8) & 0xff,
                       DAT_803dd900 +
                       (short)((uint)(iVar6 * ((int)DAT_803dd8fa - (int)(short)DAT_803dd900)) >> 8)
                       & 0xff,(int)uVar5 >> 8 & 0xff);
        }
        else {
          FUN_80019908(DAT_803dd904 & 0xff,DAT_803dd902 & 0xff,DAT_803dd900 & 0xff,
                       (int)uVar5 / 2 & 0xff);
        }
        uVar5 = (uint)*puVar4;
        if ((uVar5 < 0x15) || (uVar5 == 0xffff)) {
          if (uVar5 != 0xffff) {
            FUN_80015dc8(DAT_803dd6b0 + uVar5 * 0x24,puVar4[1],0,0);
          }
        }
        else {
          FUN_80016870();
        }
        iVar6 = *(int *)(puVar4 + 8);
        if (iVar6 != 0) {
          uVar2 = puVar4[0xb];
          if ((uVar2 & 4) == 0) {
            if ((uVar2 & 0x800) == 0) {
              uVar5 = (uint)DAT_803dd90c;
            }
            else {
              uVar5 = DAT_803dd90c * 200 >> 8;
            }
            FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar4[5] ^ 0x80000000) -
                                        DOUBLE_803e21e0),
                         (double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar4[6] ^ 0x80000000) -
                                        DOUBLE_803e21e0),iVar6,uVar5 & 0xff,0x100);
          }
          else {
            if ((uVar2 & 0x800) == 0) {
              uVar5 = (uint)DAT_803dd90c;
            }
            else {
              uVar5 = DAT_803dd90c * 200 >> 8;
            }
            FUN_8007719c((double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar4[5] + 0xbU ^ 0x80000000)
                                        - DOUBLE_803e21e0),
                         (double)(float)((double)CONCAT44(0x43300000,
                                                          (int)(short)puVar4[6] ^ 0x80000000) -
                                        DOUBLE_803e21e0),iVar6,uVar5 & 0xff,0x100);
          }
        }
        cVar1 = *(char *)(puVar4 + 0x1c);
        *(char *)(puVar4 + 0x1c) = cVar1 + -1;
        if ((char)(cVar1 + -1) < '\0') {
          *(undefined *)(puVar4 + 0x1c) = 0;
        }
      }
      else {
        cVar1 = *(char *)(puVar8 + 0x1c);
        *(char *)(puVar8 + 0x1c) = cVar1 + -1;
        if ((char)(cVar1 + -1) < '\0') {
          *(undefined *)(puVar8 + 0x1c) = 0;
        }
      }
    }
    puVar8 = puVar8 + 0x1e;
  }
  FUN_800173e4(0xff);
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286118();
  return;
}

