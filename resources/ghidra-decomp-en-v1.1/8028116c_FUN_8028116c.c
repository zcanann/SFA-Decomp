// Function: FUN_8028116c
// Entry: 8028116c
// Size: 552 bytes

void FUN_8028116c(void)

{
  ushort uVar2;
  int iVar1;
  uint uVar3;
  undefined uVar4;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  puVar7 = &DAT_803cd570;
  iVar6 = 0;
  dVar11 = (double)FLOAT_803e8518;
  dVar12 = (double)FLOAT_803e853c;
  dVar10 = (double)FLOAT_803e8558;
  dVar9 = (double)FLOAT_803e8554;
  do {
    if ((int)(uint)DAT_803defeb <= iVar6) {
      return;
    }
    for (puVar5 = (uint *)puVar7[1]; puVar5 != (uint *)0x0; puVar5 = (uint *)*puVar5) {
      if ((puVar7[2] == 0) ||
         (((DAT_803defea != '\0' && ((*puVar7 & 0x80000000) != 0)) &&
          (*(ushort *)(puVar7 + 3) < (ushort)*(byte *)(*(int *)(puVar7[1] + 0x18) + 0x47))))) {
LAB_8028124c:
        uVar3 = puVar5[6];
        if ((*(int *)(uVar3 + 8) == 0) || (*(char *)(*(int *)(uVar3 + 8) + 0x1c) != -1)) {
          if (*(int *)(uVar3 + 8) == 0) {
            uVar4 = *(undefined *)(uVar3 + 0x46);
          }
          else {
            uVar4 = *(undefined *)(*(int *)(uVar3 + 8) + 0x1c);
          }
          iVar1 = FUN_80271f14(*(undefined2 *)(uVar3 + 0x44),0x7f,0x40,uVar4,
                               (uint)((*(uint *)(uVar3 + 0x10) & 0x10) != 0));
          *(int *)(uVar3 + 0x3c) = iVar1;
          if (iVar1 != -1) {
            if ((*(uint *)(uVar3 + 0x10) & 0x20) == 0) {
              *(uint *)(uVar3 + 0x10) = *(uint *)(uVar3 + 0x10) | 0x100000;
              *(float *)(uVar3 + 0x4c) = (float)dVar11;
            }
            else {
              *(float *)(uVar3 + 0x4c) = (float)dVar12;
            }
            FUN_80280d08((double)(float)puVar5[1],(double)(float)puVar5[2],(double)(float)puVar5[3],
                         (double)(float)puVar5[4],(double)(float)puVar5[5],uVar3);
            *(uint *)(uVar3 + 0x10) = *(uint *)(uVar3 + 0x10) & 0xfffdffff;
            *(short *)(puVar7 + 3) = *(short *)(puVar7 + 3) + 1;
            if ((uint *)puVar7[2] != (uint *)0x0) {
              puVar7[2] = *(uint *)puVar7[2];
            }
            goto LAB_80281344;
          }
        }
        if ((*(uint *)(uVar3 + 0x10) & 2) == 0) {
          *(uint *)(uVar3 + 0x10) = *(uint *)(uVar3 + 0x10) | 0x40000;
          *(uint *)(uVar3 + 0x10) = *(uint *)(uVar3 + 0x10) & 0xfffdffff;
        }
      }
      else {
        dVar8 = (double)((float)puVar5[1] - *(float *)(puVar7[2] + 4));
        if (dVar9 < dVar8) {
          if (dVar10 < dVar8) {
            *(undefined2 *)(puVar5[6] + 0x48) = 0;
          }
          else {
            uVar2 = *(short *)(puVar5[6] + 0x48) + 1;
            *(ushort *)(puVar5[6] + 0x48) = uVar2;
            if (uVar2 < 0x14) goto LAB_80281344;
          }
          goto LAB_8028124c;
        }
      }
LAB_80281344:
    }
    puVar7 = puVar7 + 4;
    iVar6 = iVar6 + 1;
  } while( true );
}

