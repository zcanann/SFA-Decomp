// Function: FUN_80145304
// Entry: 80145304
// Size: 1168 bytes

void FUN_80145304(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar6;
  undefined4 uVar5;
  undefined4 *puVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined auStack152 [13];
  char local_8b;
  
  iVar2 = FUN_802860d0();
  puVar9 = *(undefined4 **)(iVar2 + 0xb8);
  if ((puVar9[0x15] & 0x200) == 0) {
    FUN_80035f00();
    FUN_8000b7bc(iVar2,0x7f);
    if ((puVar9[0x15] & 0x800) != 0) {
      puVar9[0x15] = puVar9[0x15] & 0xfffff7ff;
      puVar9[0x15] = puVar9[0x15] | 0x1000;
      iVar8 = 0;
      puVar7 = puVar9;
      do {
        FUN_8017804c(puVar7[0x1c0]);
        puVar7 = puVar7 + 1;
        iVar8 = iVar8 + 1;
      } while (iVar8 < 7);
      FUN_8000db90(iVar2,0x3dc);
      iVar8 = *(int *)(iVar2 + 0xb8);
      if (((*(byte *)(iVar8 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(iVar2 + 0xa0) || (*(short *)(iVar2 + 0xa0) < 0x29)) &&
          (iVar3 = FUN_8000b578(iVar2,0x10), iVar3 == 0)))) {
        FUN_800393f8(iVar2,iVar8 + 0x3a8,0x29d,0,0xffffffff,0);
      }
    }
    FUN_8000db90(iVar2,0x13d);
    puVar9[0x15] = puVar9[0x15] | 0x200;
    if ((*(ushort *)(param_3 + 0x6e) & 3) == 0) {
      puVar9[0x15] = puVar9[0x15] | 0x4000;
    }
    if ((*(byte *)((int)puVar9 + 0x82e) >> 5 & 1) == 0) {
      FUN_8002b588(iVar2);
      FUN_80027ab8();
      *(byte *)((int)puVar9 + 0x82e) = *(byte *)((int)puVar9 + 0x82e) & 0xbf;
    }
  }
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar8 = iVar8 + 1) {
    bVar1 = *(byte *)(param_3 + iVar8 + 0x81);
    if (bVar1 == 3) {
      *(undefined *)*puVar9 = *(undefined *)((int)puVar9 + 0x82d);
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if ((puVar9[0x15] & 0x800) == 0) {
          cVar6 = FUN_8002e04c();
          if (cVar6 != '\0') {
            puVar9[0x15] = puVar9[0x15] | 0x800;
            iVar3 = 0;
            puVar7 = puVar9;
            do {
              iVar4 = FUN_8002bdf4(0x24,0x4f0);
              *(undefined *)(iVar4 + 4) = 2;
              *(undefined *)(iVar4 + 5) = 1;
              *(short *)(iVar4 + 0x1a) = (short)iVar3;
              uVar5 = FUN_8002df90(iVar4,5,(int)*(char *)(iVar2 + 0xac),0xffffffff,
                                   *(undefined4 *)(iVar2 + 0x30));
              puVar7[0x1c0] = uVar5;
              puVar7 = puVar7 + 1;
              iVar3 = iVar3 + 1;
            } while (iVar3 < 7);
            FUN_8000bb18(iVar2,0x3db);
            FUN_8000dcbc(iVar2,0x3dc);
          }
        }
        else {
          puVar9[0x15] = puVar9[0x15] & 0xfffff7ff;
          puVar9[0x15] = puVar9[0x15] | 0x1000;
          iVar3 = 0;
          puVar7 = puVar9;
          do {
            FUN_8017804c(puVar7[0x1c0]);
            puVar7 = puVar7 + 1;
            iVar3 = iVar3 + 1;
          } while (iVar3 < 7);
          FUN_8000db90(iVar2,0x3dc);
          iVar3 = *(int *)(iVar2 + 0xb8);
          if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
              ((0x2f < *(short *)(iVar2 + 0xa0) || (*(short *)(iVar2 + 0xa0) < 0x29)))) &&
             (iVar4 = FUN_8000b578(iVar2,0x10), iVar4 == 0)) {
            FUN_800393f8(iVar2,iVar3 + 0x3a8,0x29d,0,0xffffffff,0);
          }
        }
      }
      else if (bVar1 != 0) {
        FUN_800200e8(0x186,1);
        iVar3 = FUN_8001ffb4(0x186);
        if (((iVar3 != 0) && (puVar9[499] == 0)) && (cVar6 = FUN_8002e04c(), cVar6 != '\0')) {
          FUN_80059c2c(auStack152);
          if (local_8b == '\0') {
            uVar5 = FUN_8002bdf4(0x20,0x254);
          }
          else {
            uVar5 = FUN_8002bdf4(0x20,0x244);
          }
          uVar5 = FUN_8002df90(uVar5,4,0xffffffff,0xffffffff,*(undefined4 *)(iVar2 + 0x30));
          puVar9[499] = uVar5;
          FUN_80037d2c(iVar2,puVar9[499],3);
        }
      }
    }
    else if (bVar1 == 0x2c) {
      *(uint *)(*(int *)(iVar2 + 100) + 0x30) = *(uint *)(*(int *)(iVar2 + 100) + 0x30) | 4;
    }
    else if ((bVar1 < 0x2c) && (0x2a < bVar1)) {
      *(uint *)(*(int *)(iVar2 + 100) + 0x30) = *(uint *)(*(int *)(iVar2 + 100) + 0x30) & 0xfffffffb
      ;
    }
  }
  FUN_801389e0(iVar2,puVar9,puVar9 + 0x1ea);
  FUN_801389e0(iVar2,puVar9,puVar9 + 0x1ec);
  FUN_801389e0(iVar2,puVar9,puVar9 + 0x1ee);
  FUN_80138d7c(iVar2,puVar9);
  FUN_80138b60(iVar2,puVar9);
  FUN_8006ef38((double)FLOAT_803e23e8,(double)FLOAT_803e23e8,iVar2,param_3 + 0xf0,1,puVar9 + 0x1f6,
               puVar9 + 0x3e);
  if ((puVar9[0x15] & 1) == 0) {
    uVar5 = 0;
  }
  else {
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    FUN_8003b310(iVar2,puVar9 + 0xde);
    uVar5 = (**(code **)(*DAT_803dca54 + 0x78))(iVar2,param_3,1,0xf,0x1e,0,0);
  }
  FUN_8028611c(uVar5);
  return;
}

