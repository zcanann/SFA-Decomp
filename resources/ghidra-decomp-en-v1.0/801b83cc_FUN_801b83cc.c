// Function: FUN_801b83cc
// Entry: 801b83cc
// Size: 848 bytes

void FUN_801b83cc(void)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  undefined uVar6;
  int *piVar5;
  char cVar7;
  int *piVar8;
  int iVar9;
  uint uVar10;
  undefined4 *puVar11;
  int iVar12;
  int iVar13;
  int local_28;
  undefined4 local_24 [9];
  
  iVar3 = FUN_802860d8();
  puVar11 = *(undefined4 **)(iVar3 + 0xb8);
  iVar12 = *(int *)(iVar3 + 0x4c);
  iVar4 = FUN_8001ffb4((int)*(short *)(iVar12 + 0x22));
  if (iVar4 != 0) {
    if ((*(byte *)((int)puVar11 + 0x9a7) & 4) == 0) {
      *puVar11 = *(undefined4 *)(iVar3 + 0xc);
      puVar11[1] = *(undefined4 *)(iVar3 + 0x10);
      puVar11[2] = *(undefined4 *)(iVar3 + 0x14);
    }
    else if ((*(byte *)((int)puVar11 + 0x9a7) & 2) == 0) {
      local_24[0] = 0x15;
      iVar4 = (**(code **)(*DAT_803dca9c + 0x14))
                        ((double)*(float *)(iVar3 + 0xc),(double)*(float *)(iVar3 + 0x10),
                         (double)*(float *)(iVar3 + 0x14),local_24,1,10);
      if (iVar4 != -1) {
        iVar4 = (**(code **)(*DAT_803dca9c + 0x1c))();
        (**(code **)(*DAT_803dca9c + 0x74))();
        uVar6 = (**(code **)(*DAT_803dca9c + 0x78))
                          (iVar4,puVar11 + 3,puVar11 + 0xcb,puVar11 + 0x193,puVar11 + 0x25b);
        *(undefined *)((int)puVar11 + 0x9a6) = uVar6;
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | 2;
        *puVar11 = *(undefined4 *)(iVar4 + 8);
        puVar11[1] = *(undefined4 *)(iVar4 + 0xc);
        puVar11[2] = *(undefined4 *)(iVar4 + 0x10);
      }
    }
    sVar2 = *(short *)((int)puVar11 + 0x99e) - (ushort)DAT_803db410;
    *(short *)((int)puVar11 + 0x99e) = sVar2;
    if (sVar2 < 1) {
      uVar10 = *(byte *)((int)puVar11 + 0x9a7) & 1;
      *(undefined2 *)((int)puVar11 + 0x99e) = *(undefined2 *)(puVar11 + 0x268);
      *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) & 0xfe;
      piVar5 = (int *)FUN_80036f50(0x2f,&local_28);
      iVar9 = 0;
      iVar4 = uVar10 * 2;
      bVar1 = (byte)uVar10;
      piVar8 = piVar5;
      iVar13 = local_28;
      if (0 < local_28) {
        do {
          if (*(short *)((int)puVar11 + iVar4 + 0x9a2) == *(short *)(*piVar8 + 0x46)) {
            iVar3 = *(int *)(piVar5[iVar9] + 0x4c);
            *(undefined4 *)(iVar3 + 8) = *puVar11;
            *(undefined4 *)(iVar3 + 0xc) = puVar11[1];
            *(undefined4 *)(iVar3 + 0x10) = puVar11[2];
            *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
            (**(code **)(**(int **)(piVar5[iVar9] + 0x68) + 4))(piVar5[iVar9],iVar3,1);
            FUN_80036fa4(piVar5[iVar9],0x2f);
            FUN_80036f50(0x2f,&local_28);
            iVar3 = 0;
            if (0 < local_28) {
              if ((8 < local_28) && (uVar10 = local_28 - 1U >> 3, 0 < local_28 + -8)) {
                do {
                  iVar3 = iVar3 + 8;
                  uVar10 = uVar10 - 1;
                } while (uVar10 != 0);
              }
              iVar4 = local_28 - iVar3;
              if (iVar3 < local_28) {
                do {
                  iVar4 = iVar4 + -1;
                } while (iVar4 != 0);
              }
            }
            *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
            goto LAB_801b8704;
          }
          piVar8 = piVar8 + 1;
          iVar9 = iVar9 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      cVar7 = FUN_8002e04c();
      if (cVar7 != '\0') {
        iVar4 = FUN_8002bdf4(0x24,(int)*(short *)((int)puVar11 + iVar4 + 0x9a2));
        *(undefined4 *)(iVar4 + 8) = *puVar11;
        *(undefined4 *)(iVar4 + 0xc) = puVar11[1];
        *(undefined4 *)(iVar4 + 0x10) = puVar11[2];
        *(undefined *)(iVar4 + 4) = *(undefined *)(iVar12 + 4);
        *(undefined *)(iVar4 + 6) = *(undefined *)(iVar12 + 6);
        *(undefined *)(iVar4 + 5) = *(undefined *)(iVar12 + 5);
        *(undefined *)(iVar4 + 7) = *(undefined *)(iVar12 + 7);
        *(undefined *)(iVar4 + 7) = 0xff;
        *(undefined *)(iVar4 + 3) = *(undefined *)(iVar12 + 3);
        *(undefined *)(iVar4 + 0x18) = *(undefined *)(iVar12 + 0x1c);
        *(ushort *)(iVar4 + 0x1a) = (ushort)*(byte *)(iVar12 + 0x1a);
        *(ushort *)(iVar4 + 0x1c) = (ushort)*(byte *)(iVar12 + 0x1b);
        *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
        FUN_8002df90(iVar4,5,(int)*(char *)(iVar3 + 0xac),0xffffffff,0);
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
      }
    }
  }
LAB_801b8704:
  FUN_80286124();
  return;
}

