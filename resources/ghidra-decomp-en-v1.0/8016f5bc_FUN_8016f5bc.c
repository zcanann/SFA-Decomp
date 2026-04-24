// Function: FUN_8016f5bc
// Entry: 8016f5bc
// Size: 568 bytes

/* WARNING: Removing unreachable block (ram,0x8016f7d4) */

void FUN_8016f5bc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  undefined2 uVar1;
  undefined2 uVar2;
  ushort uVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  byte bVar7;
  int *piVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860c8();
  iVar6 = (int)((ulonglong)uVar11 >> 0x20);
  piVar8 = *(int **)(iVar6 + 0xb8);
  if (((param_6 != '\0') && ((*(byte *)(piVar8 + 0x1c) & 8) == 0)) &&
     ((float)piVar8[0xf] == FLOAT_803e3330)) {
    *(undefined *)(iVar6 + 0xad) = 1;
    iVar4 = FUN_8002b588();
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dbd58)[*(byte *)((int)piVar8 + 0x71)];
    uVar1 = *(undefined2 *)(iVar6 + 4);
    uVar2 = *(undefined2 *)(iVar6 + 2);
    dVar10 = (double)*(float *)(iVar6 + 8);
    *(float *)(iVar6 + 8) = FLOAT_803e3350;
    for (bVar7 = 0; bVar7 < 5; bVar7 = bVar7 + 1) {
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x48) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x52);
      *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) =
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c) +
           *(short *)((int)piVar8 + (uint)bVar7 * 2 + 0x66);
      *(undefined2 *)(iVar6 + 4) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x48);
      *(undefined2 *)(iVar6 + 2) = *(undefined2 *)((int)piVar8 + (uint)bVar7 * 2 + 0x5c);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_8003b8f4((double)FLOAT_803e3354,iVar6,(int)uVar11,param_3,param_4,param_5);
    }
    *(undefined2 *)(iVar6 + 4) = uVar1;
    *(undefined2 *)(iVar6 + 2) = uVar2;
    *(float *)(iVar6 + 8) = (float)dVar10;
    *(undefined *)(iVar6 + 0xad) = 0;
    iVar4 = FUN_8002b588(iVar6);
    *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = (&DAT_803dbd58)[*(byte *)((int)piVar8 + 0x71)];
    FUN_8003b8f4((double)FLOAT_803e3354,iVar6,(int)uVar11,param_3,param_4,param_5);
    iVar6 = *piVar8;
    if (iVar6 != 0) {
      if ((*(char *)(iVar6 + 0x2f8) != '\0') && (*(char *)(iVar6 + 0x4c) != '\0')) {
        uVar3 = (ushort)*(byte *)(iVar6 + 0x2f9) + (short)*(char *)(iVar6 + 0x2fa);
        if (0xc < uVar3) {
          sVar5 = FUN_800221a0(0xfffffff4,0xc);
          uVar3 = uVar3 + sVar5;
          if (0xff < uVar3) {
            uVar3 = 0xff;
            *(undefined *)(*piVar8 + 0x2fa) = 0;
          }
        }
        *(char *)(*piVar8 + 0x2f9) = (char)uVar3;
      }
      if ((*(char *)(*piVar8 + 0x2f8) != '\0') && (*(char *)(*piVar8 + 0x4c) != '\0')) {
        FUN_800604b4();
      }
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286114();
  return;
}

