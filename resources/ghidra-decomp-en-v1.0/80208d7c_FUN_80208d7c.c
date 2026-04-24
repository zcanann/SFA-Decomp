// Function: FUN_80208d7c
// Entry: 80208d7c
// Size: 600 bytes

/* WARNING: Removing unreachable block (ram,0x80208fb4) */

void FUN_80208d7c(void)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f31;
  double dVar11;
  undefined8 uVar12;
  float local_58;
  float local_54;
  float local_50;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar8 = *(int *)(iVar3 + 0xb8);
  iVar7 = **(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
  *(ushort *)(iVar3 + 0xb0) = *(ushort *)(iVar3 + 0xb0) | 0x4000;
  if (*(short *)(iVar3 + 0x46) == 0x4e0) {
    DAT_80329b78 = (int)*(float *)(iVar3 + 0xc);
    local_48 = (longlong)DAT_80329b78;
    DAT_80329b7c = (int)*(float *)(iVar3 + 0x10);
    local_40 = (longlong)DAT_80329b7c;
    DAT_80329b80 = (int)*(float *)(iVar3 + 0x14);
    local_38 = (longlong)DAT_80329b80;
  }
  else {
    dVar11 = (double)FLOAT_803e64cc;
    for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar9 = iVar9 + 1) {
      FUN_80026e00(iVar7,iVar9,&local_58);
      if ((double)local_54 < dVar11) {
        dVar11 = (double)local_54;
      }
    }
    for (iVar9 = 0; iVar9 < (int)(uint)*(ushort *)(iVar7 + 0xe4); iVar9 = iVar9 + 1) {
      FUN_80026e00(iVar7,iVar9,&local_58);
      if ((double)local_54 == dVar11) {
        bVar2 = false;
        cVar1 = *(char *)(iVar8 + 0x68);
        for (iVar6 = 0; iVar6 < cVar1; iVar6 = iVar6 + 1) {
          iVar4 = iVar8 + iVar6 * 0xc;
          if ((local_58 == *(float *)(iVar4 + 4)) && (local_50 == *(float *)(iVar4 + 0xc))) {
            bVar2 = true;
            iVar6 = (int)cVar1;
          }
        }
        if (!bVar2) {
          *(float *)(iVar8 + cVar1 * 0xc + 4) = local_58;
          *(float *)(iVar8 + *(char *)(iVar8 + 0x68) * 0xc + 8) = local_54;
          *(float *)(iVar8 + *(char *)(iVar8 + 0x68) * 0xc + 0xc) = local_50;
          *(char *)(iVar8 + 0x68) = *(char *)(iVar8 + 0x68) + '\x01';
        }
      }
    }
    *(undefined *)(iVar8 + 0x69) = 0;
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - FLOAT_803e64ac;
    *(undefined2 *)(iVar8 + 0x66) = *(undefined2 *)((int)uVar12 + 0x1e);
    *(undefined2 *)(iVar8 + 100) = *(undefined2 *)((int)uVar12 + 0x20);
    uVar5 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x66));
    *(undefined *)(iVar8 + 0x6b) = uVar5;
    uVar5 = FUN_8001ffb4((int)*(short *)(iVar8 + 100));
    *(undefined *)(iVar8 + 0x6a) = uVar5;
    if (*(char *)(iVar8 + 0x6b) != '\0') {
      *(float *)(iVar3 + 0xc) = *(float *)(iVar3 + 0xc) + FLOAT_803e64d0;
      *(float *)(iVar3 + 0x14) = *(float *)(iVar3 + 0x14) + FLOAT_803e64d4;
      *(undefined *)(iVar8 + 0x69) = 4;
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286128();
  return;
}

