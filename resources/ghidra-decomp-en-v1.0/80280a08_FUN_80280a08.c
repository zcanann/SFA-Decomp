// Function: FUN_80280a08
// Entry: 80280a08
// Size: 552 bytes

void FUN_80280a08(void)

{
  undefined uVar1;
  ushort uVar3;
  int iVar2;
  uint uVar4;
  uint **ppuVar5;
  int iVar6;
  uint *puVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  puVar7 = &DAT_803cc910;
  iVar6 = 0;
  dVar11 = (double)FLOAT_803e7880;
  dVar12 = (double)FLOAT_803e78a4;
  dVar10 = (double)FLOAT_803e78c0;
  dVar9 = (double)FLOAT_803e78bc;
  do {
    if ((int)(uint)DAT_803de36b <= iVar6) {
      return;
    }
    for (ppuVar5 = (uint **)puVar7[1]; ppuVar5 != (uint **)0x0; ppuVar5 = (uint **)*ppuVar5) {
      if ((puVar7[2] == 0) ||
         (((DAT_803de36a != '\0' && ((*puVar7 & 0x80000000) != 0)) &&
          (*(ushort *)(puVar7 + 3) < (ushort)*(byte *)(*(int *)(puVar7[1] + 0x18) + 0x47))))) {
LAB_80280ae8:
        uVar4 = (uint)ppuVar5[6];
        if ((*(int *)(uVar4 + 8) == 0) || (*(char *)(*(int *)(uVar4 + 8) + 0x1c) != -1)) {
          if (*(int *)(uVar4 + 8) == 0) {
            uVar1 = *(undefined *)(uVar4 + 0x46);
          }
          else {
            uVar1 = *(undefined *)(*(int *)(uVar4 + 8) + 0x1c);
          }
          iVar2 = FUN_802717b0(*(undefined2 *)(uVar4 + 0x44),0x7f,0x40,uVar1,
                               (*(uint *)(uVar4 + 0x10) & 0x10) != 0);
          *(int *)(uVar4 + 0x3c) = iVar2;
          if (iVar2 != -1) {
            if ((*(uint *)(uVar4 + 0x10) & 0x20) == 0) {
              *(uint *)(uVar4 + 0x10) = *(uint *)(uVar4 + 0x10) | 0x100000;
              *(float *)(uVar4 + 0x4c) = (float)dVar11;
            }
            else {
              *(float *)(uVar4 + 0x4c) = (float)dVar12;
            }
            FUN_802805a4((double)(float)ppuVar5[1],(double)(float)ppuVar5[2],
                         (double)(float)ppuVar5[3],(double)(float)ppuVar5[4],
                         (double)(float)ppuVar5[5],uVar4);
            *(uint *)(uVar4 + 0x10) = *(uint *)(uVar4 + 0x10) & 0xfffdffff;
            *(short *)(puVar7 + 3) = *(short *)(puVar7 + 3) + 1;
            if ((uint *)puVar7[2] != (uint *)0x0) {
              puVar7[2] = *(uint *)puVar7[2];
            }
            goto LAB_80280be0;
          }
        }
        if ((*(uint *)(uVar4 + 0x10) & 2) == 0) {
          *(uint *)(uVar4 + 0x10) = *(uint *)(uVar4 + 0x10) | 0x40000;
          *(uint *)(uVar4 + 0x10) = *(uint *)(uVar4 + 0x10) & 0xfffdffff;
        }
      }
      else {
        dVar8 = (double)((float)ppuVar5[1] - *(float *)(puVar7[2] + 4));
        if (dVar9 < dVar8) {
          if (dVar10 < dVar8) {
            *(undefined2 *)((int)ppuVar5[6] + 0x48) = 0;
          }
          else {
            uVar3 = *(short *)((int)ppuVar5[6] + 0x48) + 1;
            *(ushort *)((int)ppuVar5[6] + 0x48) = uVar3;
            if (uVar3 < 0x14) goto LAB_80280be0;
          }
          goto LAB_80280ae8;
        }
      }
LAB_80280be0:
    }
    puVar7 = puVar7 + 4;
    iVar6 = iVar6 + 1;
  } while( true );
}

